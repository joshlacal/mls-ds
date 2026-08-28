// Clean-chat federation routing intent and participant DS resolution.
//
// This module resolves participant routing intent after signed operation admission
// but strictly BEFORE opening business database transactions or taking row locks.
// Resolved intent carries immutable routing classifications into the persistence
// plan and rechecks exact manifest bindings under lock.
//
// Routing convention:
// - Local DS: participant `ds_did` is NULL (`None`).
// - Remote DS: participant `ds_did` is the canonical base DID string (`Some(ds_did)`).
// - Remote conversation: `is_remote` is true, `sequencer_ds` is non-NULL.
// - Local conversation: `is_remote` is false, `sequencer_ds` is NULL (`None`), `sequencer_term` is 0.

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

/// Whether participant resolution may write endpoint/mapping resolution caches.
enum RoutingResolution {
    Cached,
    Uncached,
}

async fn resolve_participant_routing_with<I, S>(
    pool: &PgPool,
    resolver: Option<&DsResolver>,
    dids: I,
    resolution: RoutingResolution,
) -> Result<BTreeMap<String, Option<String>>, FederationRoutingError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut routes = BTreeMap::new();
    let Some(resolver) = resolver else {
        for did_ref in dids {
            routes.insert(did_ref.as_ref().to_string(), None);
        }
        return Ok(routes);
    };

    let self_did = resolver.self_did();
    for did_ref in dids {
        let did = did_ref.as_ref();
        let resolved = match resolution {
            RoutingResolution::Cached => resolver.resolve(did).await,
            RoutingResolution::Uncached => resolver.resolve_uncached(did).await,
        };
        let endpoint = resolved.map_err(|err| FederationRoutingError::ResolutionFailed {
            did: did.to_string(),
            reason: err.to_string(),
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
    Ok(routes)
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
    resolve_participant_routing_with(pool, resolver, dids, RoutingResolution::Cached).await
}

/// Resolve participant DIDs without writing to endpoint or mapping resolution caches.
///
/// Used by remote-prefix bootstrap admission so that admission failures perform zero database writes.
pub async fn resolve_participant_routing_uncached<I, S>(
    pool: &PgPool,
    resolver: Option<&DsResolver>,
    dids: I,
) -> Result<BTreeMap<String, Option<String>>, FederationRoutingError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    resolve_participant_routing_with(pool, resolver, dids, RoutingResolution::Uncached).await
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
