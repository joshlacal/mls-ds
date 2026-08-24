//! Clean-chat federation routing intent and participant DS resolution.
//!
//! This module resolves participant routing intent after signed operation admission
//! but strictly BEFORE opening business database transactions or taking row locks.
//! Resolved intent carries immutable routing classifications into the persistence
//! plan and rechecks exact manifest bindings under lock.
//!
//! Routing convention:
//! - Local DS: participant `ds_did` is NULL (`None`).
//! - Remote DS: participant `ds_did` is the canonical base DID string (`Some(ds_did)`).
//! - Remote conversation: `is_remote` is true, `sequencer_ds` is non-NULL.
//! - Local conversation: `is_remote` is false, `sequencer_ds` is NULL (`None`), `sequencer_term` is 0.

use sqlx::PgPool;
use std::collections::BTreeMap;
use thiserror::Error;

use crate::federation::peer_policy;
use crate::federation::resolver::DsResolver;

#[derive(Debug, Error)]
pub enum FederationRoutingError {
    #[error("participant DS resolution failed for DID '{did}': {reason}")]
    ResolutionFailed { did: String, reason: String },

    #[error("participant DS '{ds_did}' for DID '{did}' is not trusted: {reason}")]
    UntrustedPeer {
        did: String,
        ds_did: String,
        reason: String,
    },

    #[error(
        "routing drift detected under lock: expected participants {expected:?}, got {actual:?}"
    )]
    DriftDetected {
        expected: Vec<String>,
        actual: Vec<String>,
    },
}

/// Immutable conversation routing intent prepared prior to transaction start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConversationRoutingIntent {
    pub is_remote: bool,
    pub sequencer_ds: Option<String>,
    pub sequencer_term: i64,
    /// Mapping: participant bare DID -> Option<canonical remote DS DID> (None = local DS / NULL).
    pub participant_routes: BTreeMap<String, Option<String>>,
}

impl ConversationRoutingIntent {
    pub fn local_creation(participant_routes: BTreeMap<String, Option<String>>) -> Self {
        Self {
            is_remote: false,
            sequencer_ds: None,
            sequencer_term: 0,
            participant_routes,
        }
    }

    /// Recheck that the manifest participant set under lock strictly matches the pre-resolved intent.
    pub fn recheck_manifest_dids(
        &self,
        manifest_dids: &[String],
    ) -> Result<(), FederationRoutingError> {
        let manifest_set: BTreeMap<String, ()> =
            manifest_dids.iter().map(|d| (d.clone(), ())).collect();
        let intent_set: BTreeMap<String, ()> = self
            .participant_routes
            .keys()
            .map(|d| (d.clone(), ()))
            .collect();

        if manifest_set.len() != intent_set.len() || manifest_set != intent_set {
            return Err(FederationRoutingError::DriftDetected {
                expected: intent_set.into_keys().collect(),
                actual: manifest_set.into_keys().collect(),
            });
        }
        Ok(())
    }
}

/// Immutable participant routing intent for transition additions (e.g. policy addMembers).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ParticipantRoutingIntent {
    /// Mapping: participant bare DID -> Option<canonical remote DS DID> (None = local DS / NULL).
    pub participant_routes: BTreeMap<String, Option<String>>,
}

impl ParticipantRoutingIntent {
    pub fn new(participant_routes: BTreeMap<String, Option<String>>) -> Self {
        Self { participant_routes }
    }

    /// Recheck that the added participant set under lock strictly matches the pre-resolved intent.
    pub fn recheck_added_dids(&self, added_dids: &[String]) -> Result<(), FederationRoutingError> {
        let added_set: BTreeMap<String, ()> = added_dids.iter().map(|d| (d.clone(), ())).collect();
        let intent_set: BTreeMap<String, ()> = self
            .participant_routes
            .keys()
            .map(|d| (d.clone(), ()))
            .collect();

        if added_set.len() != intent_set.len() || added_set != intent_set {
            return Err(FederationRoutingError::DriftDetected {
                expected: intent_set.into_keys().collect(),
                actual: added_set.into_keys().collect(),
            });
        }
        Ok(())
    }
}

/// Resolve participant DIDs to their delivery service endpoints and verify outbound peer policy.
///
/// This MUST be called outside/before any business transaction.
pub async fn resolve_participant_routing<I, S>(
    pool: &PgPool,
    resolver: Option<&DsResolver>,
    dids: I,
) -> Result<BTreeMap<String, Option<String>>, FederationRoutingError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut routes = BTreeMap::new();
    if let Some(resolver) = resolver {
        let self_did = resolver.self_did();
        for did_ref in dids {
            let did = did_ref.as_ref();
            let endpoint = resolver.resolve(did).await.map_err(|err| {
                FederationRoutingError::ResolutionFailed {
                    did: did.to_string(),
                    reason: err.to_string(),
                }
            })?;

            if endpoint.did == self_did {
                routes.insert(did.to_string(), None);
            } else {
                peer_policy::enforce_outbound_peer_policy(pool, &endpoint.did)
                    .await
                    .map_err(|err| FederationRoutingError::UntrustedPeer {
                        did: did.to_string(),
                        ds_did: endpoint.did.clone(),
                        reason: err.to_string(),
                    })?;
                routes.insert(did.to_string(), Some(endpoint.did));
            }
        }
    } else {
        for did_ref in dids {
            routes.insert(did_ref.as_ref().to_string(), None);
        }
    }
    Ok(routes)
}
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sqlx::postgres::PgPoolOptions;
    use uuid::Uuid;

    use crate::chat_protocol::repository::transition::{
        self, ConversationHeadKind, NewConversationHead, NewParticipantPeriod, ParticipantRole,
        ParticipantStatus,
    };
    use crate::federation::resolver::DsResolver;

    async fn setup_test_pool() -> PgPool {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for federation routing integration tests");
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .expect("failed to connect to TEST_DATABASE_URL");

        let mut conn = pool.acquire().await.expect("acquire migration connection");
        let _ = sqlx::query(
            "SET chat.operation_claim_activation_approved = 'handlers-and-legacy-apis-sealed'",
        )
        .execute(&mut *conn)
        .await;
        sqlx::migrate!("./migrations")
            .run(&mut *conn)
            .await
            .expect("migration run failed in setup_test_pool");
        let _ = sqlx::query("RESET chat.operation_claim_activation_approved")
            .execute(&mut *conn)
            .await;
        pool
    }

    #[tokio::test]
    async fn test_schema_constraints_and_indexes() {
        let pool = setup_test_pool().await;
        let mut tx = pool.begin().await.unwrap();

        let convo_id = Uuid::new_v4();
        let now = Utc::now();

        // 1. Valid local conversation (is_remote = false, sequencer_ds = NULL, sequencer_term = 0)
        let local_head = NewConversationHead {
            conversation_id: convo_id,
            kind: ConversationHeadKind::Group,
            current_generation: 0,
            current_state_version: 0,
            next_entry_seq: 2,
            created_at: now,
            is_remote: false,
            sequencer_ds: None,
            sequencer_term: 0,
        };
        transition::insert_conversation_head(&mut tx, &local_head)
            .await
            .expect("local conversation head insert must succeed");

        // 2. Invalid shape: is_remote = false but sequencer_ds is Some
        let invalid_local_id = Uuid::new_v4();
        sqlx::query("SAVEPOINT invalid_local")
            .execute(&mut *tx)
            .await
            .unwrap();
        let invalid_local = sqlx::query(
            r#"
            INSERT INTO chat.conversations(
                conversation_id, kind, lifecycle, current_generation,
                current_state_version, next_entry_seq, created_at,
                is_remote, sequencer_ds, sequencer_term
            ) VALUES ($1, 'group', 'active', 0, 0, 2, $2, FALSE, 'did:web:remote.ds', 0)
            "#,
        )
        .bind(invalid_local_id)
        .bind(now)
        .execute(&mut *tx)
        .await;
        assert!(
            invalid_local.is_err(),
            "is_remote=false with non-NULL sequencer_ds must violate conversations_is_remote_shape_check"
        );
        sqlx::query("ROLLBACK TO SAVEPOINT invalid_local")
            .execute(&mut *tx)
            .await
            .unwrap();

        // 3. Invalid shape: is_remote = true but sequencer_ds is NULL
        let invalid_remote_id = Uuid::new_v4();
        sqlx::query("SAVEPOINT invalid_remote")
            .execute(&mut *tx)
            .await
            .unwrap();
        let invalid_remote = sqlx::query(
            r#"
            INSERT INTO chat.conversations(
                conversation_id, kind, lifecycle, current_generation,
                current_state_version, next_entry_seq, created_at,
                is_remote, sequencer_ds, sequencer_term
            ) VALUES ($1, 'group', 'active', 0, 0, 2, $2, TRUE, NULL, 1)
            "#,
        )
        .bind(invalid_remote_id)
        .bind(now)
        .execute(&mut *tx)
        .await;
        assert!(
            invalid_remote.is_err(),
            "is_remote=true with NULL sequencer_ds must violate conversations_is_remote_shape_check"
        );
        sqlx::query("ROLLBACK TO SAVEPOINT invalid_remote")
            .execute(&mut *tx)
            .await
            .unwrap();
        // 4. Valid remote conversation
        let valid_remote_id = Uuid::new_v4();
        let valid_remote = NewConversationHead {
            conversation_id: valid_remote_id,
            kind: ConversationHeadKind::Group,
            current_generation: 0,
            current_state_version: 0,
            next_entry_seq: 2,
            created_at: now,
            is_remote: true,
            sequencer_ds: Some("did:web:remote.catbird.blue".to_string()),
            sequencer_term: 1,
        };
        transition::insert_conversation_head(&mut tx, &valid_remote)
            .await
            .expect("remote conversation head insert must succeed");

        // 5. Participants ds_did validation: valid NULL (local) and valid bare DID (remote)
        let creator_did = format!(
            "did:web:creator{}.example.com",
            &Uuid::new_v4().simple().to_string()[..12]
        );
        let remote_did = format!(
            "did:web:remote{}.example.com",
            &Uuid::new_v4().simple().to_string()[..12]
        );
        let device_id = Uuid::new_v4();
        let transition_id = Uuid::new_v4();
        // Seed principals and device
        sqlx::query("INSERT INTO chat.principals (user_did, created_at) VALUES ($1, $2), ($3, $2)")
            .bind(&creator_did)
            .bind(now)
            .bind(&remote_did)
            .execute(&mut *tx)
            .await
            .unwrap();

        sqlx::query(
            r#"
            INSERT INTO chat.devices (
                user_did, device_id, device_name, status, dpop_jkt,
                auth_generation, capabilities, created_at, updated_at
            ) VALUES (
                $1, $2, 'test-device', 'active',
                'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE',
                1, chat.protocol_capabilities(), $3, $3
            )
            "#,
        )
        .bind(&creator_did)
        .bind(device_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .unwrap();

        // Local participant (ds_did = None)
        let local_p = NewParticipantPeriod {
            participant_period_id: Uuid::new_v4(),
            conversation_id: convo_id,
            user_did: creator_did.clone(),
            status: ParticipantStatus::Active,
            role: ParticipantRole::Admin,
            role_transition_id: transition_id,
            role_changed_at: now,
            created_by_did: creator_did.clone(),
            created_by_device_id: device_id,
            invitation: None,
            acceptance: None,
            created_at: now,
            ds_did: None,
        };
        transition::insert_participant_period(&mut tx, &local_p)
            .await
            .expect("local participant period insert must succeed");

        // Remote participant (ds_did = Some("did:web:remote.catbird.blue"))
        let remote_p = NewParticipantPeriod {
            participant_period_id: Uuid::new_v4(),
            conversation_id: convo_id,
            user_did: remote_did.clone(),
            status: ParticipantStatus::Pending,
            role: ParticipantRole::Member,
            role_transition_id: transition_id,
            role_changed_at: now,
            created_by_did: creator_did.clone(),
            created_by_device_id: device_id,
            invitation: Some(transition::ParticipantInvitation {
                invitation_transition_id: transition_id,
                invitation_entry_id: Uuid::new_v4(),
                invited_at: now,
            }),
            acceptance: None,
            created_at: now,
            ds_did: Some("did:web:remote.catbird.blue".to_string()),
        };
        transition::insert_participant_period(&mut tx, &remote_p)
            .await
            .expect("remote participant period insert must succeed");

        // Invalid participant ds_did (e.g. not a bare DID with fragment)
        sqlx::query("SAVEPOINT invalid_pdid")
            .execute(&mut *tx)
            .await
            .unwrap();
        let invalid_p_res = sqlx::query(
            r#"
            INSERT INTO chat.participants (
                participant_period_id, conversation_id, user_did, status, role,
                role_transition_id, role_changed_at, created_by_did, created_by_device_id,
                current_membership, created_at, ds_did
            ) VALUES ($1, $2, $3, 'pending', 'member', $4, $5, $3, $6, TRUE, $5, 'did:web:remote#fragment')
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(convo_id)
        .bind(&remote_did)
        .bind(transition_id)
        .bind(now)
        .bind(device_id)
        .execute(&mut *tx)
        .await;
        assert!(
            invalid_p_res.is_err(),
            "invalid ds_did with fragment must violate participants_ds_did_check"
        );
        sqlx::query("ROLLBACK TO SAVEPOINT invalid_pdid")
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn test_resolve_participant_routing_local_only() {
        let pool = setup_test_pool().await;
        let self_did = "did:web:ds1.example.com".to_string();
        let self_endpoint = "https://ds1.example.com".to_string();
        let resolver = DsResolver::new(
            pool.clone(),
            reqwest::Client::new(),
            self_did.clone(),
            self_endpoint,
            None,
            300,
        );

        let user1 = format!("did:plc:user1{}", Uuid::new_v4().simple());
        let user2 = format!("did:plc:user2{}", Uuid::new_v4().simple());
        // Cache both users to local DS
        resolver
            .cache_mapping(
                &user1,
                &crate::federation::resolver::DsEndpoint {
                    did: self_did.clone(),
                    endpoint: "https://ds1.example.com".to_string(),
                    supported_cipher_suites: None,
                    federation_capabilities: None,
                },
            )
            .await
            .unwrap();

        resolver
            .cache_mapping(
                &user2,
                &crate::federation::resolver::DsEndpoint {
                    did: self_did.clone(),
                    endpoint: "https://ds1.example.com".to_string(),
                    supported_cipher_suites: None,
                    federation_capabilities: None,
                },
            )
            .await
            .unwrap();

        let routes = resolve_participant_routing(&pool, Some(&resolver), vec![&user1, &user2])
            .await
            .expect("resolution of local participants must succeed");

        assert_eq!(routes.len(), 2);
        assert_eq!(routes.get(&user1), Some(&None));
        assert_eq!(routes.get(&user2), Some(&None));
    }

    #[tokio::test]
    async fn test_resolve_participant_routing_mixed_with_allowlisted_peer() {
        let pool = setup_test_pool().await;
        let self_did = "did:web:ds1.example.com".to_string();
        let peer_ds_did = "did:web:peer.example.com".to_string();
        let resolver = DsResolver::new(
            pool.clone(),
            reqwest::Client::new(),
            self_did.clone(),
            "https://ds1.example.com".to_string(),
            None,
            300,
        );

        // Seed allowlisted peer in federation_peers
        sqlx::query(
            r#"
            INSERT INTO federation_peers (
                ds_did, status, max_requests_per_minute, trust_score,
                rejected_request_count, invalid_token_count, created_at, updated_at
            ) VALUES ($1, 'allow', 100, 100, 0, 0, now(), now())
            ON CONFLICT (ds_did) DO UPDATE SET status = 'allow'
            "#,
        )
        .bind(&peer_ds_did)
        .execute(&pool)
        .await
        .unwrap();

        let local_user = format!("did:plc:local{}", Uuid::new_v4().simple());
        let remote_user = format!("did:plc:remote{}", Uuid::new_v4().simple());

        // Cache local user -> self_did
        resolver
            .cache_mapping(
                &local_user,
                &crate::federation::resolver::DsEndpoint {
                    did: self_did.clone(),
                    endpoint: "https://ds1.example.com".to_string(),
                    supported_cipher_suites: None,
                    federation_capabilities: None,
                },
            )
            .await
            .unwrap();

        // Cache remote user -> peer_ds_did
        resolver
            .cache_mapping(
                &remote_user,
                &crate::federation::resolver::DsEndpoint {
                    did: peer_ds_did.clone(),
                    endpoint: "https://peer.example.com".to_string(),
                    supported_cipher_suites: None,
                    federation_capabilities: None,
                },
            )
            .await
            .unwrap();

        let routes =
            resolve_participant_routing(&pool, Some(&resolver), vec![&local_user, &remote_user])
                .await
                .expect("resolution of mixed participants with allowlisted peer must succeed");

        assert_eq!(routes.len(), 2);
        assert_eq!(routes.get(&local_user), Some(&None));
        assert_eq!(routes.get(&remote_user), Some(&Some(peer_ds_did)));
    }

    #[tokio::test]
    async fn test_resolve_participant_routing_fails_closed_on_untrusted_peer() {
        let pool = setup_test_pool().await;
        let self_did = "did:web:ds1.example.com".to_string();
        let untrusted_peer_did = "did:web:untrusted.example.com".to_string();
        let resolver = DsResolver::new(
            pool.clone(),
            reqwest::Client::new(),
            self_did.clone(),
            "https://ds1.example.com".to_string(),
            None,
            300,
        );

        // Make sure untrusted peer is NOT in federation_peers (or is block/pending)
        let _ = sqlx::query("DELETE FROM federation_peers WHERE ds_did = $1")
            .bind(&untrusted_peer_did)
            .execute(&pool)
            .await;

        let remote_user = format!("did:plc:untrusted{}", Uuid::new_v4().simple());
        resolver
            .cache_mapping(
                &remote_user,
                &crate::federation::resolver::DsEndpoint {
                    did: untrusted_peer_did.clone(),
                    endpoint: "https://untrusted.example.com".to_string(),
                    supported_cipher_suites: None,
                    federation_capabilities: None,
                },
            )
            .await
            .unwrap();

        let err = resolve_participant_routing(&pool, Some(&resolver), vec![&remote_user])
            .await
            .expect_err("resolution for unallowlisted peer must fail closed");

        assert!(matches!(err, FederationRoutingError::UntrustedPeer { .. }));
    }

    #[tokio::test]
    async fn test_routing_drift_detection_under_lock() {
        let user1 = "did:plc:user1".to_string();
        let user2 = "did:plc:user2".to_string();
        let user3 = "did:plc:user3".to_string();

        let mut participant_routes = BTreeMap::new();
        participant_routes.insert(user1.clone(), None);
        participant_routes.insert(user2.clone(), Some("did:web:remote.ds".to_string()));

        let intent = ConversationRoutingIntent::local_creation(participant_routes);

        // Matching manifest -> Ok
        assert!(intent
            .recheck_manifest_dids(&[user1.clone(), user2.clone()])
            .is_ok());

        // Extra participant in manifest -> DriftDetected
        assert!(matches!(
            intent.recheck_manifest_dids(&[user1.clone(), user2.clone(), user3.clone()]),
            Err(FederationRoutingError::DriftDetected { .. })
        ));

        // Missing participant in manifest -> DriftDetected
        assert!(matches!(
            intent.recheck_manifest_dids(&[user1.clone()]),
            Err(FederationRoutingError::DriftDetected { .. })
        ));
    }

    #[tokio::test]
    async fn test_reset_preserves_sequencer_identity_and_term() {
        let pool = setup_test_pool().await;
        let mut tx = pool.begin().await.unwrap();
        let convo_id = Uuid::new_v4();
        let now = Utc::now();

        let initial_head = NewConversationHead {
            conversation_id: convo_id,
            kind: ConversationHeadKind::Group,
            current_generation: 0,
            current_state_version: 0,
            next_entry_seq: 2,
            created_at: now,
            is_remote: true,
            sequencer_ds: Some("did:web:remote.catbird.blue".to_string()),
            sequencer_term: 4,
        };
        transition::insert_conversation_head(&mut tx, &initial_head)
            .await
            .expect("insert initial conversation head");

        // Execute CAS advancing generation to 1 (Reset activation)
        let cas = transition::ConversationHeadCas {
            conversation_id: convo_id,
            expected_generation: 0,
            expected_state_version: 0,
            expected_next_entry_seq: 2,
            successor_generation: 1,
            successor_state_version: 0,
            successor_next_entry_seq: 3,
            close: None,
        };
        transition::cas_conversation_head(&mut tx, &cas)
            .await
            .expect("CAS advancing generation across reset must succeed");

        let (is_remote, sequencer_ds, sequencer_term, current_gen): (bool, Option<String>, i64, i64) =
            sqlx::query_as(
                "SELECT is_remote, sequencer_ds, sequencer_term, current_generation FROM chat.conversations WHERE conversation_id = $1",
            )
            .bind(convo_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();

        assert_eq!(current_gen, 1);
        assert_eq!(is_remote, true);
        assert_eq!(
            sequencer_ds,
            Some("did:web:remote.catbird.blue".to_string())
        );
        assert_eq!(sequencer_term, 4);

        tx.rollback().await.unwrap();
    }
}
