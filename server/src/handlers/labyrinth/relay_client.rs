//! The home-DS side of `labyrinthRelay` (`crate::labyrinth::relay`): route a
//! thread operation on a remotely sequenced conversation to its sequencer
//! over the federation's SSRF-pinned transport, under DS service auth and
//! the outbound peer policy.

use std::sync::Arc;

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use uuid::Uuid;

use crate::federation::outbound::OutboundClient;
use crate::federation::{peer_policy, DsResolver, ServiceAuthClient};
use crate::labyrinth::auth::Admission;
use crate::labyrinth::error::{LabyrinthError, LabyrinthResult};
use crate::labyrinth::relay::{passthrough_error, RelayOp, RelayRequest, NSID};
use crate::labyrinth::wire::bytes::Bytes as AtBytes;
use crate::storage::DbPool;

/// Largest relayed response accepted (a `listBatches` page of large batches).
const MAX_RELAY_RESPONSE: usize = 32 * 1024 * 1024;

/// The federation clients the relay needs, when this DS has them.
#[derive(Clone)]
pub struct Relay(Option<RelayClient>);

#[derive(Clone)]
pub struct RelayClient {
    resolver: Arc<DsResolver>,
    outbound: Arc<OutboundClient>,
    service_auth: Arc<ServiceAuthClient>,
}

impl RelayClient {
    pub fn new(
        resolver: Arc<DsResolver>,
        outbound: Arc<OutboundClient>,
        service_auth: Arc<ServiceAuthClient>,
    ) -> Self {
        Self {
            resolver,
            outbound,
            service_auth,
        }
    }

    /// Send a prepared `labyrinthRelay` request to `target` and return its
    /// response bytes, or its typed error. Responses over `max_response`
    /// bytes are refused.
    pub async fn send(
        &self,
        pool: &DbPool,
        target: &str,
        request: &RelayRequest,
        max_response: usize,
    ) -> LabyrinthResult<Vec<u8>> {
        let op = request.op.as_str();
        let unavailable = |what: &str, error: &dyn std::fmt::Display| {
            tracing::warn!(%target, op, %error, "labyrinth relay {what} failed");
            LabyrinthError::relay_unavailable()
        };
        let destination = self
            .resolver
            .resolve_ds_destination_uncached(target)
            .await
            .map_err(|e| unavailable("resolution", &e))?;
        peer_policy::enforce_outbound_peer_policy(pool, target)
            .await
            .map_err(|e| unavailable("peer policy", &e))?;
        let token = self
            .service_auth
            .sign_request(target, NSID)
            .map_err(|e| unavailable("service auth", &e))?;
        let (status, body) = self
            .outbound
            .call_procedure_pinned_raw(&destination, NSID, &token, request, max_response)
            .await
            .map_err(|e| unavailable("call", &e))?;
        if (200..300).contains(&status) {
            Ok(body)
        } else {
            Err(passthrough_error(status, &body))
        }
    }
}

impl<S> FromRequestParts<S> for Relay
where
    S: Send + Sync,
    Arc<DsResolver>: FromRef<S>,
    Arc<OutboundClient>: FromRef<S>,
    Option<Arc<ServiceAuthClient>>: FromRef<S>,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Relay(
            Option::<Arc<ServiceAuthClient>>::from_ref(state).map(|service_auth| RelayClient {
                resolver: Arc::<DsResolver>::from_ref(state),
                outbound: Arc::<OutboundClient>::from_ref(state),
                service_auth,
            }),
        ))
    }
}

/// The sequencer DS of a remotely sequenced conversation, if it is one.
pub async fn remote_sequencer(
    pool: &DbPool,
    conversation: Uuid,
) -> LabyrinthResult<Option<String>> {
    let row: Option<Option<String>> = sqlx::query_scalar(
        "SELECT CASE WHEN is_remote THEN sequencer_ds END FROM chat.conversations \
          WHERE conversation_id = $1",
    )
    .bind(conversation)
    .fetch_optional(pool)
    .await?;
    Ok(row.flatten())
}

/// What a forwarded operation carries besides the actor.
pub enum Forwarded<'a> {
    Read {
        query: &'a str,
    },
    Write {
        payload: &'a [u8],
        write_body: String,
        write_signature: String,
    },
}

impl Relay {
    /// The federation client, when this DS has service auth configured.
    pub fn client(&self) -> Option<&RelayClient> {
        self.0.as_ref()
    }

    /// Forward `op` for `actor` to `sequencer` and return the sequencer's
    /// response bytes, or its typed error.
    pub async fn forward(
        &self,
        pool: &DbPool,
        sequencer: &str,
        op: RelayOp,
        actor: &Admission,
        forwarded: Forwarded<'_>,
    ) -> LabyrinthResult<Vec<u8>> {
        self.forward_capped(pool, sequencer, op, actor, forwarded, MAX_RELAY_RESPONSE)
            .await
    }

    /// [`forward`](Self::forward) with a response size cap.
    pub async fn forward_capped(
        &self,
        pool: &DbPool,
        sequencer: &str,
        op: RelayOp,
        actor: &Admission,
        forwarded: Forwarded<'_>,
        max_response: usize,
    ) -> LabyrinthResult<Vec<u8>> {
        let client = self.0.as_ref().ok_or_else(|| {
            tracing::warn!("labyrinth relay needed but federation service auth is not configured");
            LabyrinthError::relay_unavailable()
        })?;
        let request = relay_request(op, actor, forwarded)?;
        client.send(pool, sequencer, &request, max_response).await
    }
}

/// The `labyrinthRelay` input for `op` on behalf of `actor`.
pub fn relay_request(
    op: RelayOp,
    actor: &Admission,
    forwarded: Forwarded<'_>,
) -> LabyrinthResult<RelayRequest> {
    let read = match &forwarded {
        Forwarded::Read { .. } => {
            // A forwarded read always carries the device's own claim.
            let proof = actor.read.as_ref().ok_or_else(LabyrinthError::internal)?;
            (Some(proof.header.clone()), Some(proof.signature.clone()))
        }
        Forwarded::Write { .. } => (None, None),
    };
    let (query, payload, write_body, write_signature) = match forwarded {
        Forwarded::Read { query } => (Some(query.to_owned()), None, None, None),
        Forwarded::Write {
            payload,
            write_body,
            write_signature,
        } => (
            None,
            Some(AtBytes(payload.to_vec())),
            Some(write_body),
            Some(write_signature),
        ),
    };
    Ok(RelayRequest {
        op: op.name().to_owned(),
        actor_did: actor.did.clone(),
        actor_device_id: Some(actor.device_id.hyphenated().to_string()),
        query,
        payload,
        write_body,
        write_signature,
        read_header: read.0,
        read_signature: read.1,
    })
}
