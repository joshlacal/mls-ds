#![allow(dead_code)]

#[path = "../src/chat_protocol/model.rs"]
mod model;
#[path = "../src/chat_protocol/relationship_policy.rs"]
mod relationship_policy;
#[path = "../src/chat_protocol/validation.rs"]
mod validation;

use async_trait::async_trait;
use chrono::{SecondsFormat, TimeDelta, TimeZone, Utc};
use relationship_policy::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;
use tokio::time::Instant;
use url::Url;
use validation::TrustedRequestInstant;

fn did(index: usize) -> String {
    const DIGITS: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut suffix = [b'a'; 24];
    let mut value = index;
    for slot in suffix.iter_mut().rev().take(4) {
        *slot = DIGITS[value % DIGITS.len()];
        value /= DIGITS.len();
    }
    format!("did:plc:{}", String::from_utf8(suffix.to_vec()).unwrap())
}

fn roster(size: usize) -> Vec<String> {
    let mut members: Vec<_> = (0..size).map(did).collect();
    members.sort();
    members
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn valid_config() -> RelationshipPolicyConfig {
    RelationshipPolicyConfig::new(RelationshipPolicyConfigInput {
        appview_origin: "https://public.api.bsky.app".into(),
        plc_directory_origin: "https://plc.directory".into(),
        max_concurrency: 16,
        request_rate_per_second: HARD_MAX_REQUEST_RATE,
        request_burst: HARD_MAX_REQUEST_BURST,
        total_deadline: Duration::from_secs(20),
        max_response_bytes: 256 * 1024,
        max_dns_answers: 8,
        admission_graph_capacity: MAX_ADMISSION_GRAPH_CALLS,
        declaration_http_capacity: MAX_DECLARATION_HTTP_CALLS,
        admission_source_capacity: MAX_ADMISSION_SOURCE_CALLS,
        traffic_graph_capacity: MAX_TRAFFIC_GRAPH_CALLS,
    })
    .unwrap()
}

const TEST_PROJECTION_REVISION: u64 = 7;
const TEST_FALLBACK_PROJECTION_REVISION: u64 = 7_000;

fn request_instant_at(value: chrono::DateTime<Utc>) -> TrustedRequestInstant {
    let submillisecond_nanos = value.timestamp_subsec_nanos() % 1_000_000;
    let canonical_value = if submillisecond_nanos == 0 {
        value
    } else {
        value + TimeDelta::nanoseconds(i64::from(1_000_000 - submillisecond_nanos))
    };
    let canonical = canonical_value.to_rfc3339_opts(SecondsFormat::Millis, true);
    TrustedRequestInstant::from_canonical_for_test(
        validation::CanonicalTimestamp::parse(&canonical).unwrap(),
    )
}

fn persistence_at(completed_at: chrono::DateTime<Utc>) -> TrustedRelationshipPersistenceInstant {
    TrustedRelationshipPersistenceInstant::for_test(completed_at)
}

fn relationship_decision_at(
    operation_scope: ProjectionOperationScope,
    scope: ProjectionScope,
    observed_at: chrono::DateTime<Utc>,
) -> TrustedRelationshipDecisionInstant {
    TrustedRelationshipDecisionInstant::for_test_relationship(
        "4242".to_owned(),
        operation_scope,
        scope,
        [0x91; 32],
        observed_at,
    )
}

fn traffic_decision_at(
    scope: TrafficGraphScope,
    observed_at: chrono::DateTime<Utc>,
) -> TrustedRelationshipDecisionInstant {
    TrustedRelationshipDecisionInstant::for_test_traffic(
        "4242".to_owned(),
        scope,
        [0x91; 32],
        observed_at,
    )
}

fn relationship_load_guard(
    values: &PersistedRelationshipProjection,
) -> RelationshipProjectionLoadGuard {
    RelationshipProjectionLoadGuard::for_test(values.operation_scope, values.scope.clone())
}

async fn collect_admission_projection<T: PublicTransport, C: ProjectionClock>(
    source: &HttpRelationshipSource<T>,
    clock: &C,
    request: AdmissionRequest,
) -> Result<RelationshipProjection, ProjectionRefreshFailure> {
    collect_admission_projection_for(source, clock, ProjectionOperationScope::Creation, request)
        .await
}

async fn collect_admission_projection_for<T: PublicTransport, C: ProjectionClock>(
    source: &HttpRelationshipSource<T>,
    clock: &C,
    operation_scope: ProjectionOperationScope,
    request: AdmissionRequest,
) -> Result<RelationshipProjection, ProjectionRefreshFailure> {
    relationship_policy::collect_admission_projection(
        source,
        clock,
        AllocatedProjectionRevisionGuard::for_test(TEST_PROJECTION_REVISION),
        operation_scope,
        request,
    )
    .await
}

async fn collect_block_projection<T: PublicTransport, C: ProjectionClock>(
    source: &HttpRelationshipSource<T>,
    clock: &C,
    roster: Vec<String>,
) -> Result<RelationshipProjection, ProjectionRefreshFailure> {
    collect_block_projection_for(
        source,
        clock,
        ProjectionOperationScope::RecoveryReservation,
        roster,
    )
    .await
}

async fn collect_block_projection_for<T: PublicTransport, C: ProjectionClock>(
    source: &HttpRelationshipSource<T>,
    clock: &C,
    operation_scope: ProjectionOperationScope,
    roster: Vec<String>,
) -> Result<RelationshipProjection, ProjectionRefreshFailure> {
    relationship_policy::collect_block_projection(
        source,
        clock,
        AllocatedProjectionRevisionGuard::for_test(TEST_PROJECTION_REVISION),
        operation_scope,
        roster,
    )
    .await
}

async fn collect_traffic_projection<T: PublicTransport, C: ProjectionClock>(
    source: &HttpRelationshipSource<T>,
    clock: &C,
    actor: String,
    roster: Vec<String>,
) -> Result<TrafficProjection, ProjectionRefreshFailure> {
    relationship_policy::collect_traffic_projection(
        source,
        clock,
        AllocatedProjectionRevisionGuard::for_test(TEST_PROJECTION_REVISION),
        actor,
        roster,
    )
    .await
}

#[tokio::test]
async fn post_lock_decision_time_is_distinct_from_request_and_persistence_time() {
    let source = HttpRelationshipSource::new(valid_config(), ScriptedTransport::new());
    let request = admission_request(3, AdmissionOperation::Group);
    let projection = collect_admission_projection(&source, &StepClock::new(), request.clone())
        .await
        .unwrap();
    let request_entry_time = request_instant_at(projection.started_at());
    assert!(projection.completed_at() > request_entry_time.datetime());

    let persistence_observation = persistence_at(projection.completed_at());
    projection
        .export_persisted(&source, &persistence_observation)
        .expect("post-collection observation permits first persistence");

    let post_lock_decision = relationship_decision_at(
        ProjectionOperationScope::Creation,
        projection.scope().clone(),
        projection.completed_at(),
    );
    assert_eq!(
        consume_admission_projection(
            &projection,
            ProjectionOperationScope::Creation,
            &request,
            &source,
            &post_lock_decision,
            false,
        ),
        Ok(())
    );

    let delayed_post_lock_decision = relationship_decision_at(
        ProjectionOperationScope::Creation,
        projection.scope().clone(),
        projection.completed_at() + TimeDelta::seconds(61),
    );
    assert_eq!(
        consume_admission_projection(
            &projection,
            ProjectionOperationScope::Creation,
            &request,
            &source,
            &delayed_post_lock_decision,
            false,
        ),
        Err(PolicyDenial::RelationshipPolicyUnavailable)
    );
}

#[test]
fn startup_configuration_is_canonical_bounded_and_capacity_complete() {
    let config = valid_config();
    assert_eq!(
        config.appview_origin().as_str(),
        "https://public.api.bsky.app"
    );
    assert_eq!(
        config.plc_directory_origin().as_str(),
        "https://plc.directory"
    );
    assert_ne!(config.fingerprint(), [0; 32]);
    let RelationshipAuthorityReadiness::Ready(proof) = config.readiness();
    assert_eq!(proof.roster_sizes_verified(), MAX_ROSTER_SIZE);
    assert_eq!(proof.max_admission_graph_calls(), MAX_ADMISSION_GRAPH_CALLS);
    assert_eq!(
        proof.max_declaration_http_calls(),
        MAX_DECLARATION_HTTP_CALLS
    );
    assert_eq!(
        proof.max_admission_source_calls(),
        MAX_ADMISSION_SOURCE_CALLS
    );
    assert_eq!(proof.max_traffic_graph_calls(), MAX_TRAFFIC_GRAPH_CALLS);

    for invalid in [
        "http://public.api.bsky.app",
        "https://PUBLIC.api.bsky.app",
        "https://user@public.api.bsky.app",
        "https://public.api.bsky.app/",
        "https://public.api.bsky.app/path",
        "https://public.api.bsky.app?query",
        "https://public.api.bsky.app#fragment",
        "https://public.api.bsky.app:443",
        "https://127.0.0.1",
        "https://localhost",
    ] {
        let mut input = RelationshipPolicyConfigInput::from(&config);
        input.appview_origin = invalid.into();
        assert!(
            RelationshipPolicyConfig::new(input).is_err(),
            "accepted {invalid}"
        );
    }

    let mut input = RelationshipPolicyConfigInput::from(&config);
    input.max_concurrency = 0;
    assert!(RelationshipPolicyConfig::new(input).is_err());
    let mut input = RelationshipPolicyConfigInput::from(&config);
    input.max_concurrency = HARD_MAX_CONCURRENCY + 1;
    assert!(RelationshipPolicyConfig::new(input).is_err());
    let mut input = RelationshipPolicyConfigInput::from(&config);
    input.total_deadline = Duration::ZERO;
    assert!(RelationshipPolicyConfig::new(input).is_err());
    let mut input = RelationshipPolicyConfigInput::from(&config);
    input.total_deadline = HARD_MAX_TOTAL_DEADLINE + Duration::from_millis(1);
    assert!(RelationshipPolicyConfig::new(input).is_err());
    let mut input = RelationshipPolicyConfigInput::from(&config);
    input.max_response_bytes = HARD_MAX_RESPONSE_BYTES + 1;
    assert!(RelationshipPolicyConfig::new(input).is_err());
    let mut input = RelationshipPolicyConfigInput::from(&config);
    input.admission_source_capacity = MAX_ADMISSION_SOURCE_CALLS - 1;
    assert!(RelationshipPolicyConfig::new(input).is_err());
    let mut input = RelationshipPolicyConfigInput::from(&config);
    input.request_rate_per_second = 1;
    input.request_burst = 1;
    assert!(RelationshipPolicyConfig::new(input).is_err());
}

#[test]
fn persistence_discriminants_are_closed_and_schema_exact() {
    for (scope, spelling) in [
        (ProjectionOperationScope::Creation, "creation"),
        (ProjectionOperationScope::PendingAdd, "pendingAdd"),
        (ProjectionOperationScope::Acceptance, "acceptance"),
        (
            ProjectionOperationScope::RecoveryReservation,
            "recoveryReservation",
        ),
        (
            ProjectionOperationScope::RecoveryFulfillment,
            "recoveryFulfillment",
        ),
        (ProjectionOperationScope::Traffic, "traffic"),
    ] {
        assert_eq!(scope.as_persisted_str(), spelling);
        assert_eq!(
            ProjectionOperationScope::from_persisted_str(spelling),
            Ok(scope)
        );
    }
    for (kind, spelling) in [
        (EvidenceKind::Live, "live"),
        (EvidenceKind::Fallback, "fallback"),
    ] {
        assert_eq!(kind.as_persisted_str(), spelling);
        assert_eq!(EvidenceKind::from_persisted_str(spelling), Ok(kind));
    }
    for (kind, spelling) in [
        (
            DeclarationRecordEvidenceKind::RecordPresent,
            "recordPresent",
        ),
        (
            DeclarationRecordEvidenceKind::StructuredRecordNotFound,
            "structuredRecordNotFound",
        ),
    ] {
        assert_eq!(kind.as_persisted_str(), spelling);
        assert_eq!(
            DeclarationRecordEvidenceKind::from_persisted_str(spelling),
            Ok(kind)
        );
    }
    for unknown in ["", "Live", "pending_add", "record-present", "other"] {
        assert!(ProjectionOperationScope::from_persisted_str(unknown).is_err());
        assert!(EvidenceKind::from_persisted_str(unknown).is_err());
        assert!(DeclarationRecordEvidenceKind::from_persisted_str(unknown).is_err());
    }
}

#[test]
fn configuration_fingerprint_commits_sub_millisecond_duration_precision() {
    let config = valid_config();
    let mut first = RelationshipPolicyConfigInput::from(&config);
    first.total_deadline = Duration::from_secs(20) + Duration::from_nanos(1);
    let mut second = first.clone();
    second.total_deadline = Duration::from_secs(20) + Duration::from_nanos(2);
    assert_ne!(
        RelationshipPolicyConfig::new(first).unwrap().fingerprint(),
        RelationshipPolicyConfig::new(second).unwrap().fingerprint()
    );
}

#[test]
fn admission_planner_covers_every_pair_once_for_all_roster_sizes() {
    for size in 1..=MAX_ROSTER_SIZE {
        let members = roster(size);
        let sink = members[0].clone();
        let plan = plan_admission_graph(&members, &sink).unwrap();
        let mut pairs = BTreeSet::new();
        for request in &plan.requests {
            assert!((1..=GRAPH_OTHERS_MAX).contains(&request.others.len()));
            let mut sorted = request.others.clone();
            sorted.sort();
            assert_eq!(request.others, sorted);
            for target in &request.others {
                assert_ne!(&request.actor, target);
                let pair = if request.actor < *target {
                    (request.actor.clone(), target.clone())
                } else {
                    (target.clone(), request.actor.clone())
                };
                assert!(pairs.insert(pair), "duplicate pair at roster size {size}");
            }
        }
        assert_eq!(pairs.len(), size * size.saturating_sub(1) / 2);
        assert_eq!(plan.scope.members, members);
    }
}

#[test]
fn roster_100_has_exact_regular_tournament_and_198_calls() {
    let members = roster(100);
    let sink = members[0].clone();
    let plan = plan_admission_graph(&members, &sink).unwrap();
    assert_eq!(plan.requests.len(), 198);

    let non_sink = &members[1..];
    for (index, primary) in non_sink.iter().enumerate() {
        let requests: Vec<_> = plan
            .requests
            .iter()
            .filter(|request| request.actor == *primary)
            .collect();
        assert_eq!(requests.len(), 2);
        let lengths: Vec<_> = requests
            .iter()
            .map(|request| request.others.len())
            .collect();
        assert_eq!(lengths, vec![30, 20]);
        let targets: BTreeSet<_> = requests
            .iter()
            .flat_map(|request| request.others.iter().cloned())
            .collect();
        assert_eq!(targets.len(), 50);
        assert!(targets.contains(&sink));
        for (other_index, target) in non_sink.iter().enumerate() {
            if index == other_index {
                continue;
            }
            let distance = (other_index + 99 - index) % 99;
            assert_eq!(targets.contains(target), (1..=49).contains(&distance));
        }
    }
}

#[test]
fn block_only_and_traffic_plans_are_canonical_and_bounded() {
    let members = roster(100);
    let block_plan = plan_block_only_graph(&members).unwrap();
    assert_eq!(block_plan.requests.len(), MAX_ADMISSION_GRAPH_CALLS);
    assert_eq!(block_plan.scope.sink, members[0]);

    let traffic = plan_traffic_graph(&members[0], &members).unwrap();
    assert_eq!(traffic.requests.len(), MAX_TRAFFIC_GRAPH_CALLS);
    assert_eq!(traffic.requests[0].others.len(), 30);
    assert_eq!(traffic.requests[3].others.len(), 9);
    assert!(traffic
        .requests
        .iter()
        .all(|request| request.actor == members[0]));
}

#[test]
fn did_document_requires_the_exact_atproto_pds_service() {
    let actor = did(1);
    let expected = format!("{actor}#atproto_pds");
    for id in ["#atproto_pds".to_string(), expected] {
        let body = json!({
            "id": actor,
            "service": [{
                "id": id,
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": "https://pds.example.net"
            }]
        });
        assert_eq!(
            parse_did_document(&actor, &serde_json::to_vec(&body).unwrap())
                .unwrap()
                .as_str(),
            "https://pds.example.net"
        );
    }

    let bad_documents = [
        json!({"id": actor, "service": []}),
        json!({"id": did(2), "service": [{"id":"#atproto_pds","type":"AtprotoPersonalDataServer","serviceEndpoint":"https://pds.example.net"}]}),
        json!({"id": actor, "service": [{"id":"#pds","type":"AtprotoPersonalDataServer","serviceEndpoint":"https://pds.example.net"}]}),
        json!({"id": actor, "service": [{"id":"#atproto_pds","type":"Wrong","serviceEndpoint":"https://pds.example.net"}]}),
        json!({"id": actor, "service": [{"id":"#atproto_pds","type":"AtprotoPersonalDataServer","serviceEndpoint":"http://pds.example.net"}]}),
        json!({"id": actor, "service": [{"id":"#atproto_pds","type":"AtprotoPersonalDataServer","serviceEndpoint":"https://pds.example.net/path"}]}),
        json!({"id": actor, "service": [
            {"id":"#atproto_pds","type":"AtprotoPersonalDataServer","serviceEndpoint":"https://pds.example.net"},
            {"id":format!("{actor}#atproto_pds"),"type":"AtprotoPersonalDataServer","serviceEndpoint":"https://other.example.net"}
        ]}),
    ];
    for body in bad_documents {
        assert!(parse_did_document(&actor, &serde_json::to_vec(&body).unwrap()).is_err());
    }
    assert!(parse_did_document(
        &actor,
        br#"{"id":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","id":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","service":[]}"#,
    )
    .is_err());
}

#[test]
fn declaration_success_and_structured_record_not_found_are_exact() {
    let actor = did(3);
    let uri = format!("at://{actor}/chat.bsky.actor.declaration/self");
    let record = json!({
        "uri": uri,
        "cid": "bafyreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku",
        "value": {
            "$type": "chat.bsky.actor.declaration",
            "allowIncoming": "following"
        }
    });
    let parsed =
        parse_declaration_response(&actor, 200, &serde_json::to_vec(&record).unwrap()).unwrap();
    assert_eq!(parsed.incoming(), IncomingPolicy::Following);
    assert_eq!(parsed.group(), IncomingPolicy::Following);
    assert!(!parsed.is_absent());

    let absent = parse_declaration_response(
        &actor,
        400,
        br#"{"error":"RecordNotFound","message":"missing"}"#,
    )
    .unwrap();
    assert!(absent.is_absent());
    assert_eq!(absent.incoming(), IncomingPolicy::Following);

    assert!(parse_declaration_response(&actor, 302, br#"{"error":"RecordNotFound"}"#,).is_err());
    assert!(parse_declaration_response(&actor, 500, br#"{"error":"RecordNotFound"}"#,).is_err());
    assert!(
        parse_declaration_response(&actor, 201, &serde_json::to_vec(&record).unwrap(),).is_err()
    );

    for (status, body) in [
        (404, br#"{}"#.as_slice()),
        (400, br#"{"error":"ActorNotFound"}"#.as_slice()),
        (401, br#"{"error":"AuthRequired"}"#.as_slice()),
        (500, br#"{"error":"InternalServerError"}"#.as_slice()),
        (200, br#"{"uri":null,"value":{}}"#.as_slice()),
        (200, br#"{"uri":"wrong","value":{"$type":"chat.bsky.actor.declaration","allowIncoming":"all"}}"#.as_slice()),
        (200, br#"{"uri":"at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/chat.bsky.actor.declaration/self","value":{"$type":"wrong","allowIncoming":"all"}}"#.as_slice()),
        (200, br#"{"uri":"at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/chat.bsky.actor.declaration/self","value":{"$type":"chat.bsky.actor.declaration","allowIncoming":"unknown"}}"#.as_slice()),
        (200, br#"{"uri":"at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/chat.bsky.actor.declaration/self","value":{"$type":"chat.bsky.actor.declaration","allowIncoming":null}}"#.as_slice()),
    ] {
        assert!(parse_declaration_response(&actor, status, body).is_err());
    }

    let duplicate = format!(
        r#"{{"uri":"{uri}","value":{{"$type":"chat.bsky.actor.declaration","allowIncoming":"all","allowIncoming":"none"}}}}"#
    );
    assert!(parse_declaration_response(&actor, 200, duplicate.as_bytes()).is_err());
}

#[test]
fn declaration_cid_must_be_a_canonical_parsed_cid() {
    let actor = did(3);
    let uri = format!("at://{actor}/chat.bsky.actor.declaration/self");
    for malformed in [
        "ba",
        "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!",
        "BAFYREIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "Qm00000000000000000000000000000000000000000000",
    ] {
        let record = json!({
            "uri": uri,
            "cid": malformed,
            "value": {
                "$type": "chat.bsky.actor.declaration",
                "allowIncoming": "following"
            }
        });
        assert!(
            parse_declaration_response(&actor, 200, &serde_json::to_vec(&record).unwrap()).is_err(),
            "accepted malformed or non-canonical CID {malformed}"
        );
    }
}

fn graph_body(actor: &str, targets: &[String], following: bool) -> Vec<u8> {
    let relationships: Vec<Value> = targets
        .iter()
        .map(|target| {
            let mut value = json!({
                "$type": "app.bsky.graph.defs#relationship",
                "did": target,
            });
            if following {
                value.as_object_mut().unwrap().insert(
                    "following".into(),
                    json!(format!("at://{actor}/app.bsky.graph.follow/abc")),
                );
            }
            value
        })
        .collect();
    serde_json::to_vec(&json!({"actor": actor, "relationships": relationships})).unwrap()
}

#[test]
fn graph_response_requires_exact_actor_target_set_and_strict_fields() {
    let actor = did(4);
    let targets = vec![did(5), did(6)];
    let parsed =
        parse_graph_response(&actor, &targets, &graph_body(&actor, &targets, true)).unwrap();
    assert_eq!(parsed.len(), 2);
    assert!(parsed.iter().all(|row| row.following));

    let mut wrong_actor: Value =
        serde_json::from_slice(&graph_body(&actor, &targets, true)).unwrap();
    wrong_actor["actor"] = json!(did(7));
    assert!(
        parse_graph_response(&actor, &targets, &serde_json::to_vec(&wrong_actor).unwrap()).is_err()
    );

    let mut missing: Value = serde_json::from_slice(&graph_body(&actor, &targets, true)).unwrap();
    missing["relationships"].as_array_mut().unwrap().pop();
    assert!(
        parse_graph_response(&actor, &targets, &serde_json::to_vec(&missing).unwrap()).is_err()
    );

    let mut extra: Value = serde_json::from_slice(&graph_body(&actor, &targets, true)).unwrap();
    extra["relationships"].as_array_mut().unwrap().push(json!({
        "$type":"app.bsky.graph.defs#relationship", "did": did(8)
    }));
    assert!(parse_graph_response(&actor, &targets, &serde_json::to_vec(&extra).unwrap()).is_err());

    let mut duplicate: Value = serde_json::from_slice(&graph_body(&actor, &targets, true)).unwrap();
    let first = duplicate["relationships"][0].clone();
    duplicate["relationships"][1] = first;
    assert!(
        parse_graph_response(&actor, &targets, &serde_json::to_vec(&duplicate).unwrap()).is_err()
    );

    let hostile = [
        json!({"relationships":[{"$type":"app.bsky.graph.defs#notFoundActor","actor":targets[0]}]}),
        json!({"relationships":[{"$type":"unknown","did":targets[0]}]}),
        json!({"relationships":[{"$type":"app.bsky.graph.defs#relationship","did":targets[0],"following":null}]}),
        json!({"relationships":[{"$type":"app.bsky.graph.defs#relationship","did":targets[0],"blocking":42}]}),
        json!({"relationships":[{"$type":"app.bsky.graph.defs#relationship","did":targets[0],"blockedBy":"not-an-at-uri"}]}),
    ];
    for body in hostile {
        assert!(
            parse_graph_response(&actor, &targets[..1], &serde_json::to_vec(&body).unwrap())
                .is_err()
        );
    }
    assert!(parse_graph_response(
        &actor,
        &targets[..1],
        br#"{"relationships":[{"$type":"app.bsky.graph.defs#relationship","did":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","did":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"}]}"#,
    )
    .is_err());

    let followed_by_only = serde_json::to_vec(&json!({
        "actor": actor,
        "relationships": [{
            "$type":"app.bsky.graph.defs#relationship",
            "did":targets[0],
            "followedBy":format!("at://{}/app.bsky.graph.follow/abc", targets[0]),
        }]
    }))
    .unwrap();
    let parsed = parse_graph_response(&actor, &targets[..1], &followed_by_only).unwrap();
    assert!(parsed[0].followed_by);
    assert!(
        !parsed[0].following,
        "inverse direction must never satisfy following"
    );
}

#[test]
fn graph_policy_uris_require_exact_nsid_and_record_key_grammar() {
    let actor = did(1);
    let target = did(2);
    let targets = vec![target.clone()];
    let overlong_authority = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(62)
    );
    for invalid_uri in [
        format!("at://{actor}/app.bsky.graph.follow/{}", "a".repeat(513)),
        format!("at://{actor}/app.bsky.graph.follow/bad+rkey"),
        format!("at://{actor}/app..graph.follow/abc"),
        format!("at://{actor}/1app.bsky.graph/abc"),
        format!("at://{actor}/app.bsky.-graph/abc"),
        format!("at://{actor}/app.bsky.graph.bad-name/abc"),
        format!("at://{actor}/app.bsky.graph.foll-ow/abc"),
        format!("at://{actor}/{overlong_authority}.follow/abc"),
    ] {
        let body = json!({
            "actor": actor,
            "relationships": [{
                "$type": "app.bsky.graph.defs#relationship",
                "did": target,
                "following": invalid_uri,
            }]
        });
        assert!(
            parse_graph_response(&actor, &targets, &serde_json::to_vec(&body).unwrap()).is_err(),
            "accepted malformed policy AT URI"
        );
    }

    let numeric_intermediate = json!({
        "actor": actor,
        "relationships": [{
            "$type": "app.bsky.graph.defs#relationship",
            "did": target,
            "following": format!("at://{actor}/app.123.graph/abc"),
        }]
    });
    assert!(parse_graph_response(
        &actor,
        &targets,
        &serde_json::to_vec(&numeric_intermediate).unwrap()
    )
    .is_ok());
}

#[derive(Clone)]
struct ScriptedTransport {
    state: Arc<Mutex<ScriptedState>>,
}

#[derive(Default)]
struct ScriptedState {
    requests: Vec<PublicGet>,
    declarations: BTreeMap<String, IncomingPolicy>,
    group_declarations: BTreeMap<String, IncomingPolicy>,
    blocked_pairs: BTreeMap<(String, String), usize>,
    non_following_pairs: BTreeSet<(String, String)>,
    missing_records: BTreeSet<String>,
    short_pds_service_ids: BTreeSet<String>,
    errors: VecDeque<TransportError>,
    oversize_next: bool,
}

impl ScriptedTransport {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(ScriptedState::default())),
        }
    }

    fn requests(&self) -> Vec<PublicGet> {
        self.state.lock().unwrap().requests.clone()
    }

    fn set_declaration(&self, actor: &str, incoming: IncomingPolicy) {
        self.state
            .lock()
            .unwrap()
            .declarations
            .insert(actor.into(), incoming);
    }

    fn set_group_declaration(&self, actor: &str, group: IncomingPolicy) {
        self.state
            .lock()
            .unwrap()
            .group_declarations
            .insert(actor.into(), group);
    }

    fn mark_declaration_missing(&self, actor: &str) {
        self.state
            .lock()
            .unwrap()
            .missing_records
            .insert(actor.into());
    }

    fn use_short_pds_service_id(&self, actor: &str) {
        self.state
            .lock()
            .unwrap()
            .short_pds_service_ids
            .insert(actor.into());
    }

    fn block(&self, left: &str, right: &str) {
        self.block_with_flag(left, right, 0);
    }

    fn block_with_flag(&self, left: &str, right: &str, flag: usize) {
        self.state
            .lock()
            .unwrap()
            .blocked_pairs
            .insert(ordered_pair(left, right), flag);
    }

    fn do_not_follow(&self, actor: &str, target: &str) {
        self.state
            .lock()
            .unwrap()
            .non_following_pairs
            .insert((actor.into(), target.into()));
    }

    fn fail_next(&self, error: TransportError) {
        self.state.lock().unwrap().errors.push_back(error);
    }

    fn oversize_next(&self) {
        self.state.lock().unwrap().oversize_next = true;
    }
}

fn ordered_pair(left: &str, right: &str) -> (String, String) {
    if left < right {
        (left.into(), right.into())
    } else {
        (right.into(), left.into())
    }
}

fn query_values(url: &Url, key: &str) -> Vec<String> {
    url.query_pairs()
        .filter(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
        .collect()
}

#[async_trait]
impl PublicTransport for ScriptedTransport {
    async fn get(&self, request: PublicGet) -> Result<PublicResponse, TransportError> {
        let mut state = self.state.lock().unwrap();
        state.requests.push(request.clone());
        if let Some(error) = state.errors.pop_front() {
            return Err(error);
        }
        if state.oversize_next {
            state.oversize_next = false;
            return Ok(PublicResponse::new(
                200,
                vec![b'x'; request.max_body_bytes + 1],
            ));
        }
        let path = request.url.path();
        if path.starts_with("/did:plc:") {
            let actor = path.trim_start_matches('/');
            let service_id = if state.short_pds_service_ids.contains(actor) {
                "#atproto_pds".to_owned()
            } else {
                format!("{actor}#atproto_pds")
            };
            return Ok(PublicResponse::json(
                200,
                json!({
                    "id": actor,
                    "service": [{
                        "id": service_id,
                        "type": "AtprotoPersonalDataServer",
                        "serviceEndpoint": "https://pds.example.net"
                    }]
                }),
            ));
        }
        if path == "/xrpc/com.atproto.repo.getRecord" {
            let actor = query_values(&request.url, "repo").remove(0);
            assert_eq!(
                query_values(&request.url, "collection"),
                ["chat.bsky.actor.declaration"]
            );
            assert_eq!(query_values(&request.url, "rkey"), ["self"]);
            if state.missing_records.contains(&actor) {
                return Ok(PublicResponse::json(400, json!({"error":"RecordNotFound"})));
            }
            let incoming = state
                .declarations
                .get(&actor)
                .copied()
                .unwrap_or(IncomingPolicy::Following);
            let group = state.group_declarations.get(&actor).copied();
            let mut value = json!({
                "$type": "chat.bsky.actor.declaration",
                "allowIncoming": incoming.as_str(),
            });
            if let Some(group) = group {
                value
                    .as_object_mut()
                    .unwrap()
                    .insert("allowGroupInvites".into(), json!(group.as_str()));
            }
            return Ok(PublicResponse::json(
                200,
                json!({
                    "uri": format!("at://{actor}/chat.bsky.actor.declaration/self"),
                    "cid": "bafyreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku",
                    "value": value,
                }),
            ));
        }
        if path == "/xrpc/app.bsky.graph.getRelationships" {
            let actor = query_values(&request.url, "actor").remove(0);
            let others = query_values(&request.url, "others");
            let relationships: Vec<_> = others
                .iter()
                .map(|target| {
                    let mut row = json!({
                        "$type": "app.bsky.graph.defs#relationship",
                        "did": target,
                    });
                    if !state
                        .non_following_pairs
                        .contains(&(actor.clone(), target.clone()))
                    {
                        row.as_object_mut().unwrap().insert(
                            "following".into(),
                            json!(format!("at://{actor}/app.bsky.graph.follow/abc")),
                        );
                    }
                    if let Some(flag) = state.blocked_pairs.get(&ordered_pair(&actor, target)) {
                        let field = match flag {
                            0 => "blocking",
                            1 => "blockedBy",
                            2 => "blockingByList",
                            3 => "blockedByList",
                            _ => unreachable!(),
                        };
                        row.as_object_mut().unwrap().insert(
                            field.into(),
                            json!(format!("at://{actor}/app.bsky.graph.block/abc")),
                        );
                    }
                    row
                })
                .collect();
            return Ok(PublicResponse::json(
                200,
                json!({"actor":actor,"relationships":relationships}),
            ));
        }
        panic!("unexpected public request: {}", request.url);
    }
}

#[derive(Clone)]
struct StepClock {
    current: Arc<Mutex<chrono::DateTime<Utc>>>,
}

impl StepClock {
    fn new() -> Self {
        Self {
            current: Arc::new(Mutex::new(
                Utc.with_ymd_and_hms(2026, 7, 22, 12, 0, 0).unwrap(),
            )),
        }
    }
}

impl ProjectionClock for StepClock {
    fn now(&self) -> chrono::DateTime<Utc> {
        let mut current = self.current.lock().unwrap();
        let result = *current;
        *current += TimeDelta::milliseconds(1);
        result
    }
}

struct LongCollectionClock {
    calls: AtomicUsize,
}

struct SubMicrosecondClock {
    current: Mutex<chrono::DateTime<Utc>>,
}

impl SubMicrosecondClock {
    fn new() -> Self {
        Self {
            current: Mutex::new(
                Utc.with_ymd_and_hms(2026, 7, 22, 12, 0, 0).unwrap() + TimeDelta::nanoseconds(999),
            ),
        }
    }
}

impl ProjectionClock for SubMicrosecondClock {
    fn now(&self) -> chrono::DateTime<Utc> {
        let mut current = self.current.lock().unwrap();
        let result = *current;
        *current += TimeDelta::nanoseconds(1_001);
        result
    }
}

impl LongCollectionClock {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
        }
    }
}

impl ProjectionClock for LongCollectionClock {
    fn now(&self) -> chrono::DateTime<Utc> {
        let step = self.calls.fetch_add(1, Ordering::SeqCst) as i64;
        Utc.with_ymd_and_hms(2026, 7, 22, 12, 0, 0).unwrap() + TimeDelta::seconds(31 * step)
    }
}

fn admission_request(size: usize, operation: AdmissionOperation) -> AdmissionRequest {
    let members = roster(size);
    AdmissionRequest {
        inviter: members[0].clone(),
        roster: members.clone(),
        pending_recipients: members[1..].to_vec(),
        operation,
    }
}

#[tokio::test]
async fn collection_is_pds_first_and_never_short_circuits_on_denial() {
    let transport = ScriptedTransport::new();
    let request = admission_request(4, AdmissionOperation::Group);
    transport.set_declaration(&request.pending_recipients[0], IncomingPolicy::None);
    let source = HttpRelationshipSource::new(valid_config(), transport.clone());
    let projection = collect_admission_projection(&source, &StepClock::new(), request.clone())
        .await
        .unwrap();

    let requests = transport.requests();
    assert_eq!(requests.len(), 2 * request.pending_recipients.len() + 3);
    let first_graph = requests
        .iter()
        .position(|request| request.url.path() == "/xrpc/app.bsky.graph.getRelationships")
        .unwrap();
    assert_eq!(first_graph, 2 * request.pending_recipients.len());
    assert_eq!(
        projection.declaration_count(),
        request.pending_recipients.len()
    );
    assert_eq!(projection.graph_batch_count(), 3);
    assert!(projection.completed_at() > projection.started_at());
    assert_eq!(
        consume_admission_projection(
            &projection,
            ProjectionOperationScope::Creation,
            &request,
            &source,
            &relationship_decision_at(
                ProjectionOperationScope::Creation,
                ProjectionScope::Admission(request.clone()),
                projection.completed_at(),
            ),
            false,
        ),
        Err(PolicyDenial::GroupInvitesDisabled)
    );
}

#[tokio::test]
async fn exact_urls_and_public_credential_free_requests_are_constructed() {
    let transport = ScriptedTransport::new();
    let request = admission_request(2, AdmissionOperation::Group);
    let source = HttpRelationshipSource::new(valid_config(), transport.clone());
    let projection = collect_admission_projection(&source, &StepClock::new(), request.clone())
        .await
        .unwrap();
    assert_ne!(projection.projection_id(), uuid::Uuid::nil());
    assert_ne!(projection.evidence_digest(), [0; 32]);
    let requests = transport.requests();
    assert_eq!(
        requests[0].url.as_str(),
        format!("https://plc.directory/{}", request.pending_recipients[0])
    );
    assert_eq!(
        requests[1].url.origin().ascii_serialization(),
        "https://pds.example.net"
    );
    assert_eq!(requests[1].url.path(), "/xrpc/com.atproto.repo.getRecord");
    assert_eq!(
        requests[2].url.origin().ascii_serialization(),
        "https://public.api.bsky.app"
    );
    assert_eq!(
        requests[2].url.path(),
        "/xrpc/app.bsky.graph.getRelationships"
    );
    assert!(requests
        .iter()
        .all(|request| request.credentials == PublicCredentials::None));
}

#[tokio::test]
async fn transport_failures_cannot_produce_a_completed_projection() {
    for error in [
        TransportError::Redirect,
        TransportError::Deadline,
        TransportError::UnsafeDestination,
        TransportError::DnsRebinding,
    ] {
        let transport = ScriptedTransport::new();
        transport.fail_next(error);
        let request = admission_request(2, AdmissionOperation::Direct);
        let source = HttpRelationshipSource::new(valid_config(), transport);
        let failure =
            collect_admission_projection(&source, &StepClock::new(), request.clone()).await;
        let failure = failure.expect_err("failed refresh must not yield completed evidence");
        assert!(failure.failure_count() > 0);
        assert_eq!(
            failure.started_at(),
            Utc.with_ymd_and_hms(2026, 7, 22, 12, 0, 0).unwrap()
        );
    }

    let transport = ScriptedTransport::new();
    transport.oversize_next();
    let request = admission_request(2, AdmissionOperation::Direct);
    let source = HttpRelationshipSource::new(valid_config(), transport);
    let failure = collect_admission_projection(&source, &StepClock::new(), request.clone()).await;
    assert!(failure.is_err());
}

#[tokio::test]
async fn overlong_successful_collection_is_still_a_refresh_failure() {
    let transport = ScriptedTransport::new();
    let source = HttpRelationshipSource::new(valid_config(), transport);
    let failure = collect_block_projection(&source, &LongCollectionClock::new(), roster(1))
        .await
        .expect_err("collection-duration fence must run before sealing completion");
    assert_eq!(failure.failure_count(), 1);
}

#[tokio::test]
async fn configured_rate_and_burst_are_enforced_by_the_source() {
    let mut input = RelationshipPolicyConfigInput::from(&valid_config());
    input.request_rate_per_second = 20;
    input.request_burst = 1;
    let config = RelationshipPolicyConfig::new(input).unwrap();
    let transport = ScriptedTransport::new();
    let source = HttpRelationshipSource::new(config, transport);
    let request = admission_request(2, AdmissionOperation::Direct);
    let started = Instant::now();
    let projection = collect_admission_projection(&source, &StepClock::new(), request)
        .await
        .unwrap();
    assert_ne!(projection.evidence_digest(), [0; 32]);
    assert!(started.elapsed() >= Duration::from_millis(80));
}

#[tokio::test]
async fn frozen_denial_precedence_is_exact() {
    let request = admission_request(2, AdmissionOperation::Direct);

    let transport = ScriptedTransport::new();
    transport.fail_next(TransportError::Network);
    let source = HttpRelationshipSource::new(valid_config(), transport);
    assert!(
        collect_admission_projection(&source, &StepClock::new(), request.clone())
            .await
            .is_err()
    );

    let transport = ScriptedTransport::new();
    transport.set_declaration(&request.pending_recipients[0], IncomingPolicy::None);
    transport.block(&request.inviter, &request.pending_recipients[0]);
    let source = HttpRelationshipSource::new(valid_config(), transport);
    let projection = collect_admission_projection(&source, &StepClock::new(), request.clone())
        .await
        .unwrap();
    assert_eq!(
        decision(&source, &projection, &request, true),
        PolicyDenial::BlockedRelationship
    );

    let transport = ScriptedTransport::new();
    transport.set_declaration(&request.pending_recipients[0], IncomingPolicy::None);
    let source = HttpRelationshipSource::new(valid_config(), transport);
    let projection = collect_admission_projection(&source, &StepClock::new(), request.clone())
        .await
        .unwrap();
    assert_eq!(
        decision(&source, &projection, &request, true),
        PolicyDenial::MessagesDisabled
    );

    let transport = ScriptedTransport::new();
    transport.do_not_follow(&request.pending_recipients[0], &request.inviter);
    let source = HttpRelationshipSource::new(valid_config(), transport);
    let projection = collect_admission_projection(&source, &StepClock::new(), request.clone())
        .await
        .unwrap();
    assert_eq!(
        decision(&source, &projection, &request, true),
        PolicyDenial::NotFollowedByRecipient
    );

    let transport = ScriptedTransport::new();
    let source = HttpRelationshipSource::new(valid_config(), transport);
    let projection = collect_admission_projection(&source, &StepClock::new(), request.clone())
        .await
        .unwrap();
    assert_eq!(
        decision(&source, &projection, &request, true),
        PolicyDenial::InvitationLimitReached
    );
}

#[tokio::test]
async fn declaration_none_precedes_missing_following_across_different_recipients() {
    let request = admission_request(3, AdmissionOperation::Group);
    let transport = ScriptedTransport::new();
    transport.do_not_follow(&request.pending_recipients[0], &request.inviter);
    transport.set_declaration(&request.pending_recipients[1], IncomingPolicy::None);
    let source = HttpRelationshipSource::new(valid_config(), transport);
    let projection = collect_admission_projection(&source, &StepClock::new(), request.clone())
        .await
        .unwrap();
    assert_eq!(
        consume_admission_projection(
            &projection,
            ProjectionOperationScope::Creation,
            &request,
            &source,
            &relationship_decision_at(
                ProjectionOperationScope::Creation,
                ProjectionScope::Admission(request.clone()),
                projection.completed_at(),
            ),
            false,
        ),
        Err(PolicyDenial::GroupInvitesDisabled)
    );
}

fn decision<T: PublicTransport>(
    source: &HttpRelationshipSource<T>,
    projection: &RelationshipProjection,
    request: &AdmissionRequest,
    quota: bool,
) -> PolicyDenial {
    consume_admission_projection(
        projection,
        ProjectionOperationScope::Creation,
        request,
        source,
        &relationship_decision_at(
            ProjectionOperationScope::Creation,
            ProjectionScope::Admission(request.clone()),
            projection.completed_at(),
        ),
        quota,
    )
    .unwrap_err()
}

#[tokio::test]
async fn projection_fences_scope_config_completeness_evidence_and_age() {
    let request = admission_request(3, AdmissionOperation::Group);
    let transport = ScriptedTransport::new();
    let source = HttpRelationshipSource::new(valid_config(), transport);
    let projection = collect_admission_projection(&source, &StepClock::new(), request.clone())
        .await
        .unwrap();
    assert_eq!(projection.projection_revision(), TEST_PROJECTION_REVISION);
    assert_ne!(projection.projection_id(), uuid::Uuid::nil());
    assert_ne!(projection.evidence_digest(), [0; 32]);
    assert_eq!(
        consume_admission_projection(
            &projection,
            ProjectionOperationScope::Creation,
            &request,
            &source,
            &relationship_decision_at(
                ProjectionOperationScope::Creation,
                ProjectionScope::Admission(request.clone()),
                projection.completed_at() + TimeDelta::seconds(60),
            ),
            false,
        ),
        Ok(())
    );
    assert_eq!(
        consume_admission_projection(
            &projection,
            ProjectionOperationScope::Creation,
            &request,
            &source,
            &relationship_decision_at(
                ProjectionOperationScope::Creation,
                ProjectionScope::Admission(request.clone()),
                projection.completed_at() + TimeDelta::milliseconds(60_001),
            ),
            false,
        ),
        Err(PolicyDenial::RelationshipPolicyUnavailable)
    );
    let mut other_request = request.clone();
    other_request.roster.pop();
    assert_eq!(
        consume_admission_projection(
            &projection,
            ProjectionOperationScope::Creation,
            &other_request,
            &source,
            &relationship_decision_at(
                ProjectionOperationScope::Creation,
                ProjectionScope::Admission(other_request.clone()),
                projection.completed_at(),
            ),
            false,
        ),
        Err(PolicyDenial::RelationshipPolicyUnavailable)
    );
    let mut wrong_config_input = RelationshipPolicyConfigInput::from(source.config());
    wrong_config_input.appview_origin = "https://other.api.bsky.app".into();
    let wrong_source = HttpRelationshipSource::new(
        RelationshipPolicyConfig::new(wrong_config_input).unwrap(),
        ScriptedTransport::new(),
    );
    assert_eq!(
        consume_admission_projection(
            &projection,
            ProjectionOperationScope::Creation,
            &request,
            &wrong_source,
            &relationship_decision_at(
                ProjectionOperationScope::Creation,
                ProjectionScope::Admission(request.clone()),
                projection.completed_at(),
            ),
            false,
        ),
        Err(PolicyDenial::RelationshipPolicyUnavailable)
    );
}

#[tokio::test]
async fn live_projection_consumes_its_exact_allocation_authority_once() {
    let source = HttpRelationshipSource::new(valid_config(), ScriptedTransport::new());
    let request = admission_request(3, AdmissionOperation::Group);
    let relationship = collect_admission_projection(&source, &StepClock::new(), request)
        .await
        .unwrap();
    let relationship_now = persistence_at(relationship.completed_at());
    assert!(relationship
        .export_persisted(&source, &relationship_now)
        .is_ok());
    assert!(relationship
        .export_persisted(&source, &relationship_now)
        .is_err());

    let members = roster(32);
    let traffic =
        collect_traffic_projection(&source, &StepClock::new(), members[0].clone(), members)
            .await
            .unwrap();
    let traffic_now = persistence_at(traffic.completed_at());
    assert!(traffic.export_persisted(&source, &traffic_now).is_ok());
    assert!(traffic.export_persisted(&source, &traffic_now).is_err());
}

#[tokio::test]
async fn persisted_fallback_round_trip_is_strictly_fenced_and_consumable() {
    let request = admission_request(3, AdmissionOperation::Group);
    let source = HttpRelationshipSource::new(valid_config(), ScriptedTransport::new());
    let live = collect_admission_projection(&source, &StepClock::new(), request.clone())
        .await
        .unwrap();
    let mut wrong_config_input = RelationshipPolicyConfigInput::from(source.config());
    wrong_config_input.appview_origin = "https://other.api.bsky.app".into();
    let wrong_config = RelationshipPolicyConfig::new(wrong_config_input).unwrap();
    let wrong_source = HttpRelationshipSource::new(wrong_config, ScriptedTransport::new());
    assert!(live
        .export_persisted(&wrong_source, &persistence_at(live.completed_at()))
        .is_err());
    let values = live
        .export_persisted_fallback(
            AllocatedProjectionRevisionGuard::for_test(TEST_FALLBACK_PROJECTION_REVISION),
            &source,
            &persistence_at(live.completed_at()),
        )
        .unwrap();
    assert_ne!(values.projection_id, live.projection_id().to_string());
    assert_ne!(values.projection_revision, live.projection_revision());
    assert_eq!(values.operation_scope, ProjectionOperationScope::Creation);
    assert_eq!(values.evidence_kind, EvidenceKind::Fallback);
    assert_eq!(values.appview_base, "https://public.api.bsky.app");
    assert_eq!(
        values.configuration_fingerprint,
        source.config().fingerprint()
    );
    assert_eq!(
        values.source_call_count,
        u64::try_from(2 * values.declarations.len() + live.graph_batch_count()).unwrap()
    );
    assert_eq!(
        values.canonical_did_set_sha256,
        digest(&values.canonical_did_set_bytes)
    );
    assert_eq!(
        values.aggregate_evidence_sha256,
        digest(&values.aggregate_evidence_bytes)
    );
    assert!(values
        .declarations
        .iter()
        .all(|row| row.evidence_kind == EvidenceKind::Fallback
            && row.fetch_revision != values.projection_revision
            && row.service_id == format!("{}#atproto_pds", row.recipient)
            && row.resolved_pds_origin == "https://pds.example.net"
            && row.record_evidence_kind == DeclarationRecordEvidenceKind::RecordPresent
            && row.did_request_digest != [0; 32]
            && row.did_document_digest != [0; 32]
            && row.record_request_digest != [0; 32]
            && row.record_response_digest != [0; 32]));
    assert!(values
        .relationships
        .iter()
        .all(|row| row.evidence_kind == EvidenceKind::Fallback
            && row.fetch_revision != values.projection_revision
            && row.request_digest != [0; 32]
            && row.response_digest != [0; 32]));

    let hydrated = hydrate_persisted_relationship_projection(
        values.clone(),
        &source,
        &relationship_decision_at(
            ProjectionOperationScope::Creation,
            live.scope().clone(),
            live.completed_at(),
        ),
    )
    .unwrap();
    let mut reordered_declarations = values.clone();
    reordered_declarations.declarations.reverse();
    assert_eq!(
        hydrate_persisted_relationship_projection(
            reordered_declarations,
            &source,
            &relationship_decision_at(
                ProjectionOperationScope::Creation,
                live.scope().clone(),
                live.completed_at(),
            ),
        )
        .unwrap(),
        hydrated
    );
    assert_eq!(
        consume_admission_projection(
            &hydrated,
            ProjectionOperationScope::Creation,
            &request,
            &source,
            &relationship_decision_at(
                ProjectionOperationScope::Creation,
                ProjectionScope::Admission(request.clone()),
                hydrated.completed_at(),
            ),
            false,
        ),
        Ok(())
    );

    assert!(hydrate_persisted_relationship_projection(
        values.clone(),
        &wrong_source,
        &relationship_decision_at(
            ProjectionOperationScope::Creation,
            live.scope().clone(),
            live.completed_at(),
        ),
    )
    .is_err());

    let mut aggregate_tamper = values.clone();
    aggregate_tamper.aggregate_evidence_bytes.push(0);
    aggregate_tamper.aggregate_evidence_sha256 = digest(&aggregate_tamper.aggregate_evidence_bytes);
    assert!(hydrate_persisted_relationship_projection(
        aggregate_tamper,
        &source,
        &relationship_decision_at(
            ProjectionOperationScope::Creation,
            live.scope().clone(),
            live.completed_at(),
        ),
    )
    .is_err());

    let mut tampered = values.clone();
    tampered.declarations[0].record_response_digest[0] ^= 1;
    assert!(hydrate_persisted_relationship_projection(
        tampered,
        &source,
        &relationship_decision_at(
            ProjectionOperationScope::Creation,
            live.scope().clone(),
            live.completed_at(),
        ),
    )
    .is_err());

    let other = collect_admission_projection(&source, &StepClock::new(), request.clone())
        .await
        .unwrap()
        .export_persisted_fallback(
            AllocatedProjectionRevisionGuard::for_test(TEST_FALLBACK_PROJECTION_REVISION),
            &source,
            &persistence_at(live.completed_at()),
        )
        .unwrap();
    let mut mixed = values.clone();
    mixed.relationships[0] = other.relationships[0].clone();
    assert!(hydrate_persisted_relationship_projection(
        mixed,
        &source,
        &relationship_decision_at(
            ProjectionOperationScope::Creation,
            live.scope().clone(),
            live.completed_at(),
        ),
    )
    .is_err());

    let mut mixed_kind = values.clone();
    mixed_kind.relationships[0].evidence_kind = EvidenceKind::Live;
    assert!(hydrate_persisted_relationship_projection(
        mixed_kind,
        &source,
        &relationship_decision_at(
            ProjectionOperationScope::Creation,
            live.scope().clone(),
            live.completed_at(),
        ),
    )
    .is_err());

    let mut noncanonical_uuid = values.clone();
    noncanonical_uuid.projection_id = noncanonical_uuid.projection_id.to_uppercase();
    assert!(hydrate_persisted_relationship_projection(
        noncanonical_uuid,
        &source,
        &relationship_decision_at(
            ProjectionOperationScope::Creation,
            live.scope().clone(),
            live.completed_at(),
        ),
    )
    .is_err());

    assert!(hydrate_persisted_relationship_projection(
        values,
        &source,
        &relationship_decision_at(
            ProjectionOperationScope::Creation,
            live.scope().clone(),
            live.completed_at() + TimeDelta::milliseconds(60_001),
        ),
    )
    .is_err());
}

#[tokio::test]
async fn persisted_traffic_fallback_round_trip_rejects_duplicate_revisions() {
    let members = roster(32);
    let source = HttpRelationshipSource::new(valid_config(), ScriptedTransport::new());
    let live = collect_traffic_projection(
        &source,
        &StepClock::new(),
        members[0].clone(),
        members.clone(),
    )
    .await
    .unwrap();
    let expected_scope = live.scope().clone();
    let values = live
        .export_persisted_fallback(
            AllocatedProjectionRevisionGuard::for_test(TEST_FALLBACK_PROJECTION_REVISION),
            &source,
            &persistence_at(live.completed_at()),
        )
        .unwrap();
    let wrong_scope = TrafficGraphScope {
        actor: expected_scope.members[1].clone(),
        members: expected_scope.members.clone(),
    };
    assert!(hydrate_persisted_fallback_traffic_projection(
        values.clone(),
        TrafficProjectionLoadGuard::for_test(wrong_scope.clone()),
        &source,
        &traffic_decision_at(wrong_scope, live.completed_at()),
    )
    .is_err());
    let hydrated = hydrate_persisted_fallback_traffic_projection(
        values.clone(),
        TrafficProjectionLoadGuard::for_test(expected_scope.clone()),
        &source,
        &traffic_decision_at(expected_scope.clone(), live.completed_at()),
    )
    .unwrap();
    assert_eq!(
        consume_traffic_projection(
            &hydrated,
            &source,
            &traffic_decision_at(expected_scope.clone(), hydrated.completed_at()),
        ),
        Ok(())
    );

    let colliding_revision = live
        .export_persisted_fallback(
            AllocatedProjectionRevisionGuard::for_test(1),
            &source,
            &persistence_at(live.completed_at()),
        )
        .unwrap();
    let collision_revisions = colliding_revision
        .relationships
        .iter()
        .map(|row| row.fetch_revision)
        .collect::<BTreeSet<_>>();
    assert!(!collision_revisions.contains(&colliding_revision.projection_revision));
    assert_eq!(collision_revisions.len(), live.graph_batch_count());
    hydrate_persisted_fallback_traffic_projection(
        colliding_revision,
        TrafficProjectionLoadGuard::for_test(expected_scope.clone()),
        &source,
        &traffic_decision_at(expected_scope.clone(), live.completed_at()),
    )
    .unwrap();

    let mut duplicate_revision = values;
    assert_eq!(duplicate_revision.relationships.len(), 31);
    duplicate_revision.relationships[30].fetch_revision =
        duplicate_revision.relationships[0].fetch_revision;
    assert!(hydrate_persisted_traffic_projection(
        duplicate_revision,
        &source,
        &traffic_decision_at(expected_scope, live.completed_at()),
    )
    .is_err());
}

#[tokio::test]
async fn persisted_times_survive_postgres_microsecond_round_trip() {
    let members = roster(3);
    let source = HttpRelationshipSource::new(valid_config(), ScriptedTransport::new());
    let live = collect_traffic_projection(
        &source,
        &SubMicrosecondClock::new(),
        members[0].clone(),
        members,
    )
    .await
    .unwrap();
    let mut values = live
        .export_persisted(&source, &persistence_at(live.completed_at()))
        .unwrap();
    let postgres_round_trip = |value: chrono::DateTime<Utc>| {
        chrono::DateTime::from_timestamp_micros(value.timestamp_micros()).unwrap()
    };
    values.started_at = postgres_round_trip(values.started_at);
    values.completed_at = postgres_round_trip(values.completed_at);
    for row in &mut values.relationships {
        row.fetched_at = postgres_round_trip(row.fetched_at);
    }

    assert_eq!(
        hydrate_persisted_traffic_projection(
            values,
            &source,
            &traffic_decision_at(live.scope().clone(), live.completed_at()),
        )
        .unwrap(),
        live
    );
}

#[tokio::test]
async fn persisted_graph_rows_regroup_only_as_the_exact_canonical_batches() {
    let members = roster(32);
    let source = HttpRelationshipSource::new(valid_config(), ScriptedTransport::new());
    let live = collect_traffic_projection(
        &source,
        &StepClock::new(),
        members[0].clone(),
        members.clone(),
    )
    .await
    .unwrap();
    let expected_scope = live.scope().clone();
    let values = live
        .export_persisted(&source, &persistence_at(live.completed_at()))
        .unwrap();

    assert_eq!(values.relationships.len(), 31);
    assert!(values.relationships[..30]
        .iter()
        .enumerate()
        .all(
            |(index, row)| row.fetch_revision == values.relationships[0].fetch_revision
                && row.actor == expected_scope.actor
                && usize::from(row.batch_ordinal) == index
        ));
    assert_ne!(
        values.relationships[0].fetch_revision,
        values.relationships[30].fetch_revision
    );
    assert_eq!(values.relationships[30].batch_ordinal, 0);
    assert_eq!(
        values
            .relationships
            .iter()
            .map(|row| &row.target)
            .collect::<Vec<_>>(),
        expected_scope.members[1..].iter().collect::<Vec<_>>()
    );

    let rejects = |candidate: PersistedTrafficProjection| {
        let decision = traffic_decision_at(candidate.scope.clone(), live.completed_at());
        assert!(hydrate_persisted_traffic_projection(candidate, &source, &decision,).is_err());
    };

    let mut missing = values.clone();
    missing.relationships.remove(1);
    rejects(missing);

    let mut duplicate = values.clone();
    let duplicated_relationship = duplicate.relationships[0].clone();
    duplicate.relationships.insert(1, duplicated_relationship);
    rejects(duplicate);

    let mut reordered = values.clone();
    reordered.relationships.reverse();
    assert_eq!(
        hydrate_persisted_traffic_projection(
            reordered,
            &source,
            &traffic_decision_at(expected_scope.clone(), live.completed_at()),
        )
        .unwrap(),
        live
    );

    let mut mixed_revision = values.clone();
    mixed_revision.relationships[1].fetch_revision += 1;
    rejects(mixed_revision);

    let mut mixed_ordinal = values.clone();
    mixed_ordinal.relationships[1].batch_ordinal += 1;
    rejects(mixed_ordinal);

    let mut mixed_digest = values.clone();
    mixed_digest.relationships[1].request_digest[0] ^= 1;
    rejects(mixed_digest);

    let mut mixed_time = values.clone();
    mixed_time.relationships[1].fetched_at += TimeDelta::milliseconds(1);
    rejects(mixed_time);

    let mut extra = values.clone();
    let mut row = extra.relationships[0].clone();
    row.target = did(200);
    extra.relationships.push(row);
    rejects(extra);
}

#[tokio::test]
async fn persisted_projection_rejects_rehashed_noncanonical_or_mismatched_metadata() {
    let request = admission_request(3, AdmissionOperation::Group);
    let source = HttpRelationshipSource::new(valid_config(), ScriptedTransport::new());
    let live = collect_admission_projection(&source, &StepClock::new(), request.clone())
        .await
        .unwrap();
    let values = live
        .export_persisted(&source, &persistence_at(live.completed_at()))
        .unwrap();
    let rejects = |candidate: PersistedRelationshipProjection| {
        let decision = relationship_decision_at(
            candidate.operation_scope,
            candidate.scope.clone(),
            live.completed_at(),
        );
        assert!(hydrate_persisted_relationship_projection(candidate, &source, &decision,).is_err());
    };

    let mut did_set = values.clone();
    did_set.canonical_did_set_bytes.push(0);
    did_set.canonical_did_set_sha256 = digest(&did_set.canonical_did_set_bytes);
    rejects(did_set);

    let mut aggregate = values.clone();
    aggregate.aggregate_evidence_bytes.push(0);
    aggregate.aggregate_evidence_sha256 = digest(&aggregate.aggregate_evidence_bytes);
    rejects(aggregate);

    let mut source_count = values.clone();
    source_count.source_call_count += 1;
    rejects(source_count);

    let mut operation = values.clone();
    operation.operation_scope = ProjectionOperationScope::PendingAdd;
    rejects(operation);

    let mut scope_digest = values.clone();
    scope_digest.scope_digest[0] ^= 1;
    rejects(scope_digest);

    let mut appview = values.clone();
    appview.appview_base = "https://other.api.bsky.app".into();
    rejects(appview);

    let mut config = values.clone();
    config.configuration_fingerprint[0] ^= 1;
    rejects(config);

    let mut kind = values.clone();
    kind.evidence_kind = EvidenceKind::Fallback;
    rejects(kind);

    let mut service = values.clone();
    service.declarations[0].service_id = "#other".into();
    rejects(service);

    let mut declaration_policy = values.clone();
    declaration_policy.declarations[0].resolved_group_policy = IncomingPolicy::None;
    rejects(declaration_policy);

    let mut declaration_kind = values.clone();
    declaration_kind.declarations[0].record_evidence_kind =
        DeclarationRecordEvidenceKind::StructuredRecordNotFound;
    rejects(declaration_kind);

    let mut declaration_missing = values.clone();
    declaration_missing.declarations.pop();
    rejects(declaration_missing);

    let mut declaration_extra = values.clone();
    let duplicated_declaration = declaration_extra.declarations[0].clone();
    declaration_extra.declarations.push(duplicated_declaration);
    rejects(declaration_extra);
}

#[tokio::test]
async fn operation_scope_cannot_be_relabelled_before_or_after_restart() {
    let request = admission_request(3, AdmissionOperation::Group);
    let source = HttpRelationshipSource::new(valid_config(), ScriptedTransport::new());
    let live = collect_admission_projection(&source, &StepClock::new(), request.clone())
        .await
        .unwrap();
    let expected_scope = ProjectionScope::Admission(request);

    let persisted = live
        .export_persisted_fallback(
            AllocatedProjectionRevisionGuard::for_test(TEST_FALLBACK_PROJECTION_REVISION),
            &source,
            &persistence_at(live.completed_at()),
        )
        .unwrap();
    assert_eq!(
        persisted.operation_scope,
        ProjectionOperationScope::Creation
    );
    assert_eq!(live.operation_scope(), ProjectionOperationScope::Creation);
    assert_eq!(
        consume_admission_projection(
            &live,
            ProjectionOperationScope::PendingAdd,
            match &expected_scope {
                ProjectionScope::Admission(request) => request,
                ProjectionScope::BlockOnly(_) => unreachable!(),
            },
            &source,
            &relationship_decision_at(
                ProjectionOperationScope::PendingAdd,
                expected_scope.clone(),
                live.completed_at(),
            ),
            false,
        ),
        Err(PolicyDenial::RelationshipPolicyUnavailable)
    );

    assert!(hydrate_persisted_fallback_relationship_projection(
        persisted.clone(),
        RelationshipProjectionLoadGuard::for_test(
            ProjectionOperationScope::PendingAdd,
            expected_scope.clone(),
        ),
        &source,
        &relationship_decision_at(
            ProjectionOperationScope::PendingAdd,
            expected_scope.clone(),
            live.completed_at(),
        ),
    )
    .is_err());

    let restarted = hydrate_persisted_fallback_relationship_projection(
        persisted,
        RelationshipProjectionLoadGuard::for_test(
            ProjectionOperationScope::Creation,
            expected_scope.clone(),
        ),
        &source,
        &relationship_decision_at(
            ProjectionOperationScope::Creation,
            expected_scope.clone(),
            live.completed_at(),
        ),
    )
    .unwrap();
    assert_eq!(
        restarted.operation_scope(),
        ProjectionOperationScope::Creation
    );
    assert_eq!(
        consume_admission_projection(
            &restarted,
            ProjectionOperationScope::PendingAdd,
            match &expected_scope {
                ProjectionScope::Admission(request) => request,
                ProjectionScope::BlockOnly(_) => unreachable!(),
            },
            &source,
            &relationship_decision_at(
                ProjectionOperationScope::PendingAdd,
                expected_scope.clone(),
                restarted.completed_at(),
            ),
            false,
        ),
        Err(PolicyDenial::RelationshipPolicyUnavailable)
    );
}

#[tokio::test]
async fn fallback_snapshot_cannot_collide_with_its_live_projection_identity() {
    let request = admission_request(3, AdmissionOperation::Group);
    let source = HttpRelationshipSource::new(valid_config(), ScriptedTransport::new());
    let live = collect_admission_projection(&source, &StepClock::new(), request.clone())
        .await
        .unwrap();
    let fallback = live
        .export_persisted_fallback(
            AllocatedProjectionRevisionGuard::for_test(TEST_FALLBACK_PROJECTION_REVISION),
            &source,
            &persistence_at(live.completed_at()),
        )
        .unwrap();

    assert_ne!(fallback.projection_id, live.projection_id().to_string());
    assert_ne!(fallback.projection_revision, live.projection_revision());
}

#[tokio::test]
async fn fallback_identity_remaps_fetch_revisions_when_the_new_revision_collides() {
    let request = admission_request(3, AdmissionOperation::Group);
    let source = HttpRelationshipSource::new(valid_config(), ScriptedTransport::new());
    let live = collect_admission_projection(&source, &StepClock::new(), request)
        .await
        .unwrap();
    let fallback = live
        .export_persisted_fallback(
            AllocatedProjectionRevisionGuard::for_test(1),
            &source,
            &persistence_at(live.completed_at()),
        )
        .unwrap();

    let revisions = fallback
        .declarations
        .iter()
        .map(|row| row.fetch_revision)
        .chain(fallback.relationships.iter().map(|row| row.fetch_revision))
        .collect::<BTreeSet<_>>();
    assert!(!revisions.contains(&fallback.projection_revision));
    assert_eq!(
        revisions.len(),
        fallback.declarations.len() + live.graph_batch_count()
    );
    let load_guard = relationship_load_guard(&fallback);
    hydrate_persisted_fallback_relationship_projection(
        fallback,
        load_guard,
        &source,
        &relationship_decision_at(
            ProjectionOperationScope::Creation,
            live.scope().clone(),
            live.completed_at(),
        ),
    )
    .unwrap();
}

#[tokio::test]
async fn source_identity_is_restart_stable_and_rejects_a_forged_transport_profile() {
    let request = admission_request(3, AdmissionOperation::Group);
    let source = HttpRelationshipSource::new(valid_config(), ScriptedTransport::new());
    let live = collect_admission_projection(&source, &StepClock::new(), request)
        .await
        .unwrap();
    let persisted = live
        .export_persisted(&source, &persistence_at(live.completed_at()))
        .unwrap();

    let restarted = HttpRelationshipSource::new(valid_config(), ScriptedTransport::new());
    let live_load_guard = relationship_load_guard(&persisted);
    hydrate_persisted_live_relationship_projection(
        persisted.clone(),
        live_load_guard,
        &restarted,
        &relationship_decision_at(
            ProjectionOperationScope::Creation,
            live.scope().clone(),
            live.completed_at(),
        ),
    )
    .unwrap();

    let forged = HttpRelationshipSource::with_untrusted_source_for_test(
        valid_config(),
        ScriptedTransport::new(),
    );
    let forged_load_guard = relationship_load_guard(&persisted);
    assert!(hydrate_persisted_live_relationship_projection(
        persisted,
        forged_load_guard,
        &forged,
        &relationship_decision_at(
            ProjectionOperationScope::Creation,
            live.scope().clone(),
            live.completed_at(),
        ),
    )
    .is_err());
}

#[tokio::test]
async fn hydration_requires_exact_evidence_kind_and_trusted_decision_time() {
    let request = admission_request(3, AdmissionOperation::Group);
    let source = HttpRelationshipSource::new(valid_config(), ScriptedTransport::new());
    let live = collect_admission_projection(&source, &StepClock::new(), request)
        .await
        .unwrap();
    let persisted_live = live
        .export_persisted(&source, &persistence_at(live.completed_at()))
        .unwrap();

    let fallback_as_live_load_guard = relationship_load_guard(&persisted_live);
    assert!(hydrate_persisted_fallback_relationship_projection(
        persisted_live.clone(),
        fallback_as_live_load_guard,
        &source,
        &relationship_decision_at(
            ProjectionOperationScope::Creation,
            live.scope().clone(),
            live.completed_at(),
        ),
    )
    .is_err());
    let stale_live_load_guard = relationship_load_guard(&persisted_live);
    assert!(hydrate_persisted_live_relationship_projection(
        persisted_live,
        stale_live_load_guard,
        &source,
        &relationship_decision_at(
            ProjectionOperationScope::Creation,
            live.scope().clone(),
            live.completed_at() - TimeDelta::milliseconds(1),
        ),
    )
    .is_err());

    let persisted_fallback = live
        .export_persisted_fallback(
            AllocatedProjectionRevisionGuard::for_test(TEST_FALLBACK_PROJECTION_REVISION),
            &source,
            &persistence_at(live.completed_at()),
        )
        .unwrap();
    let live_as_fallback_load_guard = relationship_load_guard(&persisted_fallback);
    assert!(hydrate_persisted_live_relationship_projection(
        persisted_fallback.clone(),
        live_as_fallback_load_guard,
        &source,
        &relationship_decision_at(
            ProjectionOperationScope::Creation,
            live.scope().clone(),
            live.completed_at(),
        ),
    )
    .is_err());
    let fallback_load_guard = relationship_load_guard(&persisted_fallback);
    hydrate_persisted_fallback_relationship_projection(
        persisted_fallback,
        fallback_load_guard,
        &source,
        &relationship_decision_at(
            ProjectionOperationScope::Creation,
            live.scope().clone(),
            live.completed_at(),
        ),
    )
    .unwrap();
}

#[tokio::test]
async fn persisted_declarations_retain_exact_present_absent_and_group_policy_evidence() {
    let request = admission_request(3, AdmissionOperation::Group);
    let transport = ScriptedTransport::new();
    transport.mark_declaration_missing(&request.pending_recipients[0]);
    transport.use_short_pds_service_id(&request.pending_recipients[0]);
    transport.set_declaration(&request.pending_recipients[1], IncomingPolicy::All);
    transport.set_group_declaration(&request.pending_recipients[1], IncomingPolicy::None);
    let source = HttpRelationshipSource::new(valid_config(), transport);
    let live = collect_admission_projection(&source, &StepClock::new(), request.clone())
        .await
        .unwrap();
    let values = live
        .export_persisted(&source, &persistence_at(live.completed_at()))
        .unwrap();

    let absent = &values.declarations[0];
    assert_eq!(
        absent.record_evidence_kind,
        DeclarationRecordEvidenceKind::StructuredRecordNotFound
    );
    assert_eq!(absent.incoming, IncomingPolicy::Following);
    assert_eq!(absent.allow_group_invites, None);
    assert_eq!(absent.resolved_group_policy, IncomingPolicy::Following);
    assert_eq!(absent.cid, None);
    assert_eq!(absent.service_id, "#atproto_pds");

    let present = &values.declarations[1];
    assert_eq!(
        present.record_evidence_kind,
        DeclarationRecordEvidenceKind::RecordPresent
    );
    assert_eq!(present.incoming, IncomingPolicy::All);
    assert_eq!(present.allow_group_invites, Some(IncomingPolicy::None));
    assert_eq!(present.resolved_group_policy, IncomingPolicy::None);
    assert!(present.cid.is_some());
    assert_eq!(
        present.service_id,
        format!("{}#atproto_pds", present.recipient)
    );
}

#[tokio::test]
async fn persisted_singleton_block_fallback_retains_kind_without_rows() {
    let members = roster(1);
    let source = HttpRelationshipSource::new(valid_config(), ScriptedTransport::new());
    let live = collect_block_projection(&source, &StepClock::new(), members.clone())
        .await
        .unwrap();
    let values = live
        .export_persisted_fallback(
            AllocatedProjectionRevisionGuard::for_test(TEST_FALLBACK_PROJECTION_REVISION),
            &source,
            &persistence_at(live.completed_at()),
        )
        .unwrap();
    assert_eq!(values.evidence_kind, EvidenceKind::Fallback);
    assert_eq!(values.source_call_count, 0);
    assert!(values.relationships.is_empty());
    let hydrated = hydrate_persisted_relationship_projection(
        values,
        &source,
        &relationship_decision_at(
            ProjectionOperationScope::RecoveryReservation,
            live.scope().clone(),
            live.completed_at(),
        ),
    )
    .unwrap();
    assert_eq!(
        consume_block_projection(
            &hydrated,
            ProjectionOperationScope::RecoveryReservation,
            &members,
            &source,
            &relationship_decision_at(
                ProjectionOperationScope::RecoveryReservation,
                hydrated.scope().clone(),
                hydrated.completed_at(),
            ),
        ),
        Ok(())
    );
}

#[tokio::test]
async fn block_only_skips_declarations_and_traffic_never_exceeds_four_calls() {
    let transport = ScriptedTransport::new();
    let source = HttpRelationshipSource::new(valid_config(), transport.clone());
    let members = roster(100);
    let block_projection = collect_block_projection(&source, &StepClock::new(), members.clone())
        .await
        .unwrap();
    assert_eq!(block_projection.declaration_count(), 0);
    assert_eq!(
        block_projection.graph_batch_count(),
        MAX_ADMISSION_GRAPH_CALLS
    );
    assert!(transport
        .requests()
        .iter()
        .all(|request| { request.url.path() == "/xrpc/app.bsky.graph.getRelationships" }));
    assert_eq!(
        consume_block_projection(
            &block_projection,
            ProjectionOperationScope::RecoveryReservation,
            &block_projection_scope_roster(&block_projection),
            &source,
            &relationship_decision_at(
                ProjectionOperationScope::RecoveryReservation,
                block_projection.scope().clone(),
                block_projection.completed_at(),
            ),
        ),
        Ok(())
    );

    let transport = ScriptedTransport::new();
    let source = HttpRelationshipSource::new(valid_config(), transport);
    let traffic =
        collect_traffic_projection(&source, &StepClock::new(), members[0].clone(), members)
            .await
            .unwrap();
    assert_eq!(traffic.graph_batch_count(), MAX_TRAFFIC_GRAPH_CALLS);
    assert_eq!(
        consume_traffic_projection(
            &traffic,
            &source,
            &traffic_decision_at(traffic.scope().clone(), traffic.completed_at()),
        ),
        Ok(())
    );
}

#[tokio::test]
async fn one_member_block_projection_is_a_valid_zero_request_projection() {
    let transport = ScriptedTransport::new();
    let source = HttpRelationshipSource::new(valid_config(), transport.clone());
    let members = roster(1);
    let projection = collect_block_projection(&source, &StepClock::new(), members.clone())
        .await
        .unwrap();
    assert_eq!(projection.graph_batch_count(), 0);
    assert!(transport.requests().is_empty());
    assert_eq!(
        consume_block_projection(
            &projection,
            ProjectionOperationScope::RecoveryReservation,
            &members,
            &source,
            &relationship_decision_at(
                ProjectionOperationScope::RecoveryReservation,
                projection.scope().clone(),
                projection.completed_at(),
            ),
        ),
        Ok(())
    );
}

fn block_projection_scope_roster(projection: &RelationshipProjection) -> Vec<String> {
    match projection.scope() {
        ProjectionScope::BlockOnly(scope) => scope.members.clone(),
        _ => panic!("expected block-only scope"),
    }
}

#[tokio::test]
async fn maximum_admission_budget_is_exact_and_block_consume_denies_all_four_flags() {
    let request = admission_request(100, AdmissionOperation::Group);
    let transport = ScriptedTransport::new();
    let source = HttpRelationshipSource::new(valid_config(), transport.clone());
    let projection = collect_admission_projection(&source, &StepClock::new(), request.clone())
        .await
        .unwrap();
    assert_eq!(projection.declaration_count(), 99);
    assert_eq!(projection.graph_batch_count(), MAX_ADMISSION_GRAPH_CALLS);
    assert_eq!(transport.requests().len(), MAX_ADMISSION_SOURCE_CALLS);

    for field in 0..4 {
        let transport = ScriptedTransport::new();
        let members = roster(2);
        transport.block_with_flag(&members[0], &members[1], field);
        let source = HttpRelationshipSource::new(valid_config(), transport);
        let projection = collect_block_projection(&source, &StepClock::new(), members.clone())
            .await
            .unwrap();
        assert_eq!(
            consume_block_projection(
                &projection,
                ProjectionOperationScope::RecoveryReservation,
                &members,
                &source,
                &relationship_decision_at(
                    ProjectionOperationScope::RecoveryReservation,
                    projection.scope().clone(),
                    projection.completed_at(),
                ),
            ),
            Err(PolicyDenial::BlockedRelationship)
        );
    }
}

#[derive(Clone)]
struct SlowTransport {
    inner: ScriptedTransport,
    delay: Duration,
    in_flight: Arc<AtomicUsize>,
    peak_in_flight: Arc<AtomicUsize>,
}

impl SlowTransport {
    fn new(inner: ScriptedTransport, delay: Duration) -> Self {
        Self {
            inner,
            delay,
            in_flight: Arc::new(AtomicUsize::new(0)),
            peak_in_flight: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn peak_in_flight(&self) -> usize {
        self.peak_in_flight.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl PublicTransport for SlowTransport {
    async fn get(&self, request: PublicGet) -> Result<PublicResponse, TransportError> {
        let active = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak_in_flight.fetch_max(active, Ordering::SeqCst);
        tokio::time::sleep(self.delay).await;
        let result = self.inner.get(request).await;
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        result
    }
}

#[tokio::test]
async fn slow_maximum_roster_finishes_under_one_shared_deadline_with_real_concurrency() {
    let mut input = RelationshipPolicyConfigInput::from(&valid_config());
    input.total_deadline = Duration::from_secs(2);
    let transport = SlowTransport::new(ScriptedTransport::new(), Duration::from_millis(20));
    let source = HttpRelationshipSource::new(
        RelationshipPolicyConfig::new(input).unwrap(),
        transport.clone(),
    );
    let request = admission_request(MAX_ROSTER_SIZE, AdmissionOperation::Group);
    let started = Instant::now();
    let projection = collect_admission_projection(&source, &StepClock::new(), request)
        .await
        .expect("bounded concurrent collection should meet its absolute deadline");
    assert_eq!(projection.declaration_count(), MAX_ROSTER_SIZE - 1);
    assert_eq!(projection.graph_batch_count(), MAX_ADMISSION_GRAPH_CALLS);
    assert!(transport.peak_in_flight() >= 8);
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[derive(Clone)]
struct QueueResolver {
    answers: ResolverAnswerQueue,
    delay: Duration,
}

type ResolverAnswerQueue = Arc<Mutex<VecDeque<Result<Vec<SocketAddr>, TransportError>>>>;

#[async_trait]
impl DnsResolver for QueueResolver {
    async fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, TransportError> {
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        self.answers.lock().unwrap().pop_front().unwrap()
    }
}

fn resolver(answers: Vec<Vec<&str>>) -> QueueResolver {
    QueueResolver {
        answers: Arc::new(Mutex::new(
            answers
                .into_iter()
                .map(|answer| {
                    Ok(answer
                        .into_iter()
                        .map(|address| address.parse().unwrap())
                        .collect())
                })
                .collect(),
        )),
        delay: Duration::ZERO,
    }
}

#[tokio::test]
async fn pinned_transport_rejects_private_mixed_rebinding_and_dns_caps() {
    let request = PublicGet::new(
        Url::parse("https://authority.example.net/xrpc/test").unwrap(),
        Instant::now() + Duration::from_secs(1),
        1024,
    );
    let transport =
        ReqwestPinnedTransport::new(resolver(vec![vec!["93.184.216.34:443"]]), 8).unwrap();
    let pin = transport.pin_destination(&request).await.unwrap();
    assert_eq!(
        pin.addresses(),
        &["93.184.216.34:443".parse::<SocketAddr>().unwrap()]
    );

    let transport = ReqwestPinnedTransport::new(
        resolver(vec![vec!["93.184.216.34:443"], vec!["127.0.0.1:443"]]),
        8,
    )
    .unwrap();
    transport.pin_destination(&request).await.unwrap();
    assert_eq!(
        transport.pin_destination(&request).await,
        Err(TransportError::UnsafeDestination)
    );

    let transport =
        ReqwestPinnedTransport::new(resolver(vec![vec!["93.184.216.34:443", "10.0.0.1:443"]]), 8)
            .unwrap();
    assert_eq!(
        transport.pin_destination(&request).await,
        Err(TransportError::UnsafeDestination)
    );

    let transport =
        ReqwestPinnedTransport::new(resolver(vec![vec!["93.184.216.34:443", "1.1.1.1:443"]]), 1)
            .unwrap();
    assert_eq!(
        transport.pin_destination(&request).await,
        Err(TransportError::DnsCapacity)
    );

    let transport =
        ReqwestPinnedTransport::new(resolver(vec![vec!["93.184.216.34:8443"]]), 8).unwrap();
    assert_eq!(
        transport.pin_destination(&request).await,
        Err(TransportError::UnsafeDestination)
    );
}

#[tokio::test]
async fn pinned_transport_has_no_proxy_no_redirect_and_one_deadline() {
    let profile = ReqwestPinnedTransport::<QueueResolver>::security_profile();
    assert!(profile.no_proxy);
    assert!(profile.reject_redirects);
    assert!(profile.dns_pinned);
    assert!(profile.public_only);
    assert!(profile.credential_free);

    let slow = QueueResolver {
        answers: Arc::new(Mutex::new(VecDeque::from([Ok(vec!["93.184.216.34:443"
            .parse()
            .unwrap()])]))),
        delay: Duration::from_millis(50),
    };
    let transport = ReqwestPinnedTransport::new(slow, 8).unwrap();
    let request = PublicGet::new(
        Url::parse("https://authority.example.net/xrpc/test").unwrap(),
        Instant::now() + Duration::from_millis(5),
        1024,
    );
    assert_eq!(
        transport.pin_destination(&request).await,
        Err(TransportError::Deadline)
    );
}

#[test]
fn public_ip_filter_rejects_every_private_or_reserved_class() {
    for raw in [
        "0.0.0.0",
        "10.0.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "192.0.2.1",
        "192.168.0.1",
        "198.18.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "fe80::1",
        "fc00::1",
        "ff02::1",
        "64:ff9b::a00:1",
        "64:ff9b::7f00:1",
        "64:ff9b::a9fe:a9fe",
        "64:ff9b::c000:201",
        "64:ff9b::f000:1",
        "64:ff9b:1::808:808",
        "::ffff:8.8.8.8",
        "2001:db8::1",
        "3fff::1",
        "4000::1",
        "8000::1",
        "5f00::1",
    ] {
        assert!(
            !ip_is_public(raw.parse::<IpAddr>().unwrap()),
            "accepted {raw}"
        );
    }
    for raw in [
        "1.1.1.1",
        "8.8.8.8",
        "64:ff9b::808:808",
        "2001:4860:4860::8888",
    ] {
        assert!(
            ip_is_public(raw.parse::<IpAddr>().unwrap()),
            "rejected {raw}"
        );
    }
}
