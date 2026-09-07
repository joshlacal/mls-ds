use super::{
    CanonicalDeviceIdentity, CanonicalLockScope, ConversationEventLockScope, PreludeError,
};
use uuid::Uuid;

const TRANSACTION_ID: &str = "event-scope-transaction";

fn device(did: &str, suffix: u8) -> CanonicalDeviceIdentity {
    let id = Uuid::parse_str(&format!("00000000-0000-4000-8000-0000000000{suffix:02x}")).unwrap();
    CanonicalDeviceIdentity::new(did, id)
}

fn required(devices: Vec<CanonicalDeviceIdentity>) -> CanonicalLockScope {
    CanonicalLockScope::new(Vec::new(), devices).unwrap()
}

fn locked(devices: Vec<CanonicalDeviceIdentity>) -> ConversationEventLockScope {
    ConversationEventLockScope {
        transaction_id: TRANSACTION_ID.to_owned(),
        principals: required(devices.clone()).principals().to_vec(),
        devices: required(devices).devices().to_vec(),
    }
}

#[test]
fn event_scope_rejects_an_unlocked_principal_before_its_first_device_enrolls() {
    let actor = device("did:web:actor.example.com", 1);
    let scope = locked(vec![actor.clone()]);
    let required = CanonicalLockScope::new(
        vec!["did:web:new-participant.example.com".to_owned()],
        vec![actor],
    )
    .unwrap();
    assert!(matches!(
        scope.require_subset(TRANSACTION_ID, &required),
        Err(PreludeError::ScopeDrift)
    ));
}

#[test]
fn event_scope_accepts_exact_recipient_set_in_its_transaction() {
    let actor = device("did:web:actor.example.com", 1);
    let peer = device("did:web:peer.example.com", 2);
    let scope = locked(vec![actor.clone(), peer.clone()]);

    scope
        .require_subset(TRANSACTION_ID, &required(vec![peer, actor]))
        .unwrap();
}

#[test]
fn event_scope_accepts_separate_fanouts_covered_by_one_transaction_union() {
    let actor = device("did:web:actor.example.com", 1);
    let welcome_recipient = device("did:web:invited.example.com", 2);
    let historical_recipient = device("did:web:former.example.com", 3);
    let scope = locked(vec![
        actor.clone(),
        welcome_recipient.clone(),
        historical_recipient.clone(),
    ]);

    scope
        .require_subset(TRANSACTION_ID, &required(vec![welcome_recipient]))
        .unwrap();
    scope
        .require_subset(TRANSACTION_ID, &required(vec![actor, historical_recipient]))
        .unwrap();
}

#[test]
fn event_scope_rejects_another_transaction_even_for_exact_recipients() {
    let actor = device("did:web:actor.example.com", 1);
    let scope = locked(vec![actor.clone()]);

    assert!(matches!(
        scope.require_subset("different-transaction", &required(vec![actor])),
        Err(PreludeError::ForeignTransaction)
    ));
}

#[test]
fn event_scope_rejects_one_unseen_sibling_device_of_a_locked_principal() {
    let actor = device("did:web:actor.example.com", 1);
    let known_peer_device = device("did:web:peer.example.com", 2);
    let unseen_peer_device = device("did:web:peer.example.com", 3);
    let scope = locked(vec![actor.clone(), known_peer_device.clone()]);

    assert!(matches!(
        scope.require_subset(
            TRANSACTION_ID,
            &required(vec![actor, known_peer_device, unseen_peer_device]),
        ),
        Err(PreludeError::ScopeDrift)
    ));
}

#[test]
fn event_scope_rejects_one_unseen_principal_device_among_known_recipients() {
    let actor = device("did:web:actor.example.com", 1);
    let known_peer = device("did:web:peer.example.com", 2);
    let added_peer = device("did:web:added.example.com", 3);
    let scope = locked(vec![actor.clone(), known_peer.clone()]);

    assert!(matches!(
        scope.require_subset(
            TRANSACTION_ID,
            &required(vec![actor, known_peer, added_peer]),
        ),
        Err(PreludeError::ScopeDrift)
    ));
}

#[test]
fn event_scope_matches_the_did_and_device_pair_not_the_uuid_alone() {
    let actor = device("did:web:actor.example.com", 1);
    let other_principal_same_uuid = device("did:web:other.example.com", 1);
    let scope = locked(vec![actor]);

    assert!(matches!(
        scope.require_subset(TRANSACTION_ID, &required(vec![other_principal_same_uuid])),
        Err(PreludeError::ScopeDrift)
    ));
}

#[test]
fn event_scope_for_current_actor_does_not_cover_a_former_participant_recipient() {
    let new_actor = device("did:web:new-actor.example.com", 1);
    let former_participant = device("did:web:former.example.com", 2);
    let scope = locked(vec![new_actor.clone()]);

    scope
        .require_subset(TRANSACTION_ID, &required(vec![new_actor.clone()]))
        .unwrap();
    assert!(matches!(
        scope.require_subset(
            TRANSACTION_ID,
            &required(vec![new_actor, former_participant]),
        ),
        Err(PreludeError::ScopeDrift)
    ));
}
