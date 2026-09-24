//! A real `MLSOrchestrator` over the live shipping fixture, used to read the
//! exact `DirectRequestView` an app renders (`refresh_request_preview`).
//!
//! Real: the device's native MLS context and store, the shared-core request
//! projection, and every HTTP exchange (client-produced XRPC forwarded through
//! the normal scoped service-auth verifier). Only app-metadata storage and the
//! credential record are the canonical core-test mocks from
//! `catbird-mls/tests`, exactly as every core orchestrator test uses them.
//! Transport methods outside the request projection fail loudly.

use std::sync::Arc;

use catbird_mls::orchestrator::{
    api_client::MLSAPIClient,
    canonical_transport::{GatewayResponse, PreparedRequest},
    CredentialStore, MLSOrchestrator, OrchestratorConfig, OrchestratorError,
};
use catbird_mls::MLSContext;

#[path = "../../../../catbird-mls/tests/mock_credentials.rs"]
pub mod mock_credentials;
#[path = "../../../../catbird-mls/tests/mock_storage.rs"]
pub mod mock_storage;

use mock_credentials::MockCredentials;
use mock_storage::MockStorage;

pub struct LiveApiClient {
    service: crate::encrypted_requests::ServiceIdentity,
    client: reqwest::Client,
    base_url: String,
    /// Recipient packages the test obtained out of band; the router has no
    /// ordinary package-claim read.
    key_packages: Vec<catbird_mls::orchestrator::KeyPackageRef>,
    /// Every forwarded exchange (NSID, status, response body), in order.
    exchanges: std::sync::Mutex<Vec<(String, u16, Vec<u8>)>>,
}

impl LiveApiClient {
    /// A standalone host transport for `service`, for reading the live pages
    /// a production host would hand to the core.
    pub fn for_test(
        service: &crate::encrypted_requests::ServiceIdentity,
        client: &reqwest::Client,
        base_url: &str,
    ) -> Self {
        Self {
            service: service.clone(),
            client: client.clone(),
            base_url: base_url.to_owned(),
            key_packages: Vec::new(),
            exchanges: Default::default(),
        }
    }

    /// The recorded responses to `nsid`, oldest first.
    pub fn responses(&self, nsid: &str) -> Vec<(u16, Vec<u8>)> {
        self.exchanges
            .lock()
            .unwrap()
            .iter()
            .filter(|(recorded, _, _)| recorded == nsid)
            .map(|(_, status, body)| (*status, body.clone()))
            .collect()
    }
}

fn outside_projection(method: &str) -> OrchestratorError {
    OrchestratorError::Api(format!("{method} is outside the direct-request projection path"))
}

type ApiResult<T> = catbird_mls::orchestrator::Result<T>;

#[async_trait::async_trait]
impl MLSAPIClient for LiveApiClient {
    async fn is_authenticated_as(&self, did: &str) -> bool {
        did == self.service.did
    }

    async fn current_did(&self) -> Option<String> {
        Some(self.service.did.clone())
    }

    async fn submit_prepared_request(&self, request: PreparedRequest) -> ApiResult<GatewayResponse> {
        let (path, query) = match request.path.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (request.path.as_str(), None),
        };
        let nsid = path
            .strip_prefix("/xrpc/")
            .ok_or_else(|| OrchestratorError::Api(format!("unexpected path {path}")))?;
        let method = match request.method.as_str() {
            "GET" => reqwest::Method::GET,
            "POST" => reqwest::Method::POST,
            other => return Err(OrchestratorError::Api(format!("method {other}"))),
        };
        let (status, body) = self
            .service
            .forward_exact_service_request(
                &self.client,
                &self.base_url,
                method,
                nsid,
                query,
                request.body.as_deref(),
            )
            .await
            .map_err(|error| OrchestratorError::Api(format!("{error:#}")))?;
        self.exchanges
            .lock()
            .unwrap()
            .push((nsid.to_owned(), status.as_u16(), body.clone()));
        Ok(GatewayResponse {
            status: status.as_u16(),
            content_type: Some("application/json".into()),
            body,
        })
    }

    /// Canonical `getConversations` inventory mapped to host views, as a
    /// production host does (the canonical state is the core's own decoder).
    async fn get_conversations(
        &self,
        _limit: u32,
        _cursor: Option<&str>,
    ) -> ApiResult<catbird_mls::orchestrator::ConversationListPage> {
        use base64::Engine as _;
        use catbird_mls::orchestrator::{ConversationView, MemberRole, MemberView};
        let query = format!(
            "actorDeviceId={}&limit=100&supportedProtocolVersions=1&supportedProtocolVersions=2",
            self.service.device_id
        );
        let (status, body) = self
            .service
            .forward_exact_service_request(
                &self.client,
                &self.base_url,
                reqwest::Method::GET,
                "blue.catbird.chat.getConversations",
                Some(&query),
                None,
            )
            .await
            .map_err(|error| OrchestratorError::Api(format!("{error:#}")))?;
        if status != reqwest::StatusCode::OK {
            return Err(OrchestratorError::ServerError {
                status: status.as_u16(),
                body: String::from_utf8_lossy(&body).into(),
            });
        }
        let invalid = |what: &str| OrchestratorError::Serialization(format!("inventory {what}"));
        let page: serde_json::Value =
            serde_json::from_slice(&body).map_err(|_| invalid("JSON"))?;
        let mut conversations = Vec::new();
        for item in page["items"].as_array().into_iter().flatten() {
            if item["$type"] != "blue.catbird.chat.defs#conversationInventoryState" {
                continue;
            }
            let state = &item["state"];
            let coordinates = &state["coordinates"];
            let group = coordinates["groupId"]["$bytes"]
                .as_str()
                .or_else(|| coordinates["groupId"].as_str())
                .ok_or_else(|| invalid("groupId"))?;
            let group = base64::engine::general_purpose::STANDARD
                .decode(group)
                .map_err(|_| invalid("groupId"))?;
            let canonical = catbird_mls::orchestrator::canonical_transport::decode_conversation_state(
                &serde_json::to_vec(state).map_err(|_| invalid("state"))?,
            )
            .map_err(|error| invalid(&error.to_string()))?;
            conversations.push(ConversationView {
                group_id: hex::encode(group),
                conversation_id: coordinates["conversationId"]
                    .as_str()
                    .ok_or_else(|| invalid("conversationId"))?
                    .to_owned(),
                epoch: coordinates["epoch"].as_u64().ok_or_else(|| invalid("epoch"))?,
                members: state["participants"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|participant| {
                        Some(MemberView {
                            did: participant["userDid"].as_str()?.to_owned(),
                            role: if participant["role"] == "admin" {
                                MemberRole::Admin
                            } else {
                                MemberRole::Member
                            },
                        })
                    })
                    .collect(),
                metadata: None,
                created_at: None,
                updated_at: None,
                sequencer_did: None,
                canonical_state: Some(canonical),
            });
        }
        Ok(catbird_mls::orchestrator::ConversationListPage {
            conversations,
            cursor: None,
        })
    }

    /// Canonical `getEntries` page mapped exactly as a production host does:
    /// every presented entry goes through `IncomingEnvelope::from_canonical_entry`.
    async fn get_messages(
        &self,
        convo_id: &str,
        cursor: Option<&str>,
        limit: u32,
        _message_type: Option<&str>,
        _from_epoch: Option<u32>,
        _to_epoch: Option<u32>,
    ) -> ApiResult<(Vec<catbird_mls::orchestrator::IncomingEnvelope>, Option<String>)> {
        let after = cursor.unwrap_or("0");
        let query = format!(
            "actorDeviceId={}&conversationId={convo_id}&afterSeq={after}&limit={}",
            self.service.device_id,
            limit.clamp(1, 100)
        );
        let (status, body) = self
            .service
            .forward_exact_service_request(
                &self.client,
                &self.base_url,
                reqwest::Method::GET,
                "blue.catbird.chat.getEntries",
                Some(&query),
                None,
            )
            .await
            .map_err(|error| OrchestratorError::Api(format!("{error:#}")))?;
        if status != reqwest::StatusCode::OK {
            return Err(OrchestratorError::ServerError {
                status: status.as_u16(),
                body: String::from_utf8_lossy(&body).into(),
            });
        }
        let page: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|error| OrchestratorError::Serialization(error.to_string()))?;
        let mut envelopes = Vec::new();
        for entry in page["entries"].as_array().into_iter().flatten() {
            if let Some(envelope) =
                catbird_mls::orchestrator::IncomingEnvelope::from_canonical_entry(entry, convo_id)?
            {
                envelopes.push(envelope);
            }
        }
        let next = (page["hasMore"] == true)
            .then(|| page["nextAfterSeq"].as_u64().map(|seq| seq.to_string()))
            .flatten();
        Ok((envelopes, next))
    }

    async fn get_key_packages(
        &self,
        _actor_device_id: &str,
        dids: &[String],
    ) -> ApiResult<Vec<catbird_mls::orchestrator::KeyPackageRef>> {
        if self.key_packages.is_empty() {
            return Err(outside_projection("get_key_packages"));
        }
        Ok(self
            .key_packages
            .iter()
            .filter(|package| dids.contains(&package.did))
            .cloned()
            .collect())
    }

    async fn get_key_package_stats(&self) -> ApiResult<catbird_mls::orchestrator::KeyPackageStats> {
        Err(outside_projection("get_key_package_stats"))
    }

    async fn sync_key_packages(
        &self,
        _local_hashes: &[String],
        _device_id: &str,
    ) -> ApiResult<catbird_mls::orchestrator::KeyPackageSyncResult> {
        Err(outside_projection("sync_key_packages"))
    }

    async fn list_devices(
        &self,
        _actor_device_id: &str,
    ) -> ApiResult<Vec<catbird_mls::orchestrator::DeviceInfo>> {
        Err(outside_projection("list_devices"))
    }

    async fn get_group_info(&self, _convo_id: &str) -> ApiResult<Vec<u8>> {
        Err(outside_projection("get_group_info"))
    }
}

pub type LiveOrchestrator = MLSOrchestrator<MockStorage, LiveApiClient, MockCredentials, MLSContext>;

/// An initialized orchestrator for `service`'s exact device over `context`,
/// trusting the fixture's published receipt authority document.
pub async fn live_orchestrator(
    context: Arc<MLSContext>,
    service: &crate::encrypted_requests::ServiceIdentity,
    client: &reqwest::Client,
    base_url: &str,
    receipt_authority_document: Vec<u8>,
) -> anyhow::Result<LiveOrchestrator> {
    let credentials = MockCredentials::new();
    credentials.set_request_authority_document(receipt_authority_document);
    live_orchestrator_with_credentials(context, service, client, base_url, credentials).await
}

/// Same as `live_orchestrator`, over caller-populated credentials (for example
/// authorized device keys read from the live `getDeviceKey` RPC).
pub async fn live_orchestrator_with_credentials(
    context: Arc<MLSContext>,
    service: &crate::encrypted_requests::ServiceIdentity,
    client: &reqwest::Client,
    base_url: &str,
    credentials: MockCredentials,
) -> anyhow::Result<LiveOrchestrator> {
    live_orchestrator_with_key_packages(context, service, client, base_url, credentials, Vec::new())
        .await
}

/// Same, with recipient key packages the test provisioned out of band.
pub async fn live_orchestrator_with_key_packages(
    context: Arc<MLSContext>,
    service: &crate::encrypted_requests::ServiceIdentity,
    client: &reqwest::Client,
    base_url: &str,
    credentials: MockCredentials,
    key_packages: Vec<catbird_mls::orchestrator::KeyPackageRef>,
) -> anyhow::Result<LiveOrchestrator> {
    credentials
        .store_device_uuid(&service.did, &service.device_id.to_string())
        .await?;
    credentials.store_mls_did(&service.did, &service.did).await?;
    let orchestrator = MLSOrchestrator::new(
        context,
        Arc::new(MockStorage::new()),
        Arc::new(LiveApiClient {
            service: service.clone(),
            client: client.clone(),
            base_url: base_url.to_owned(),
            key_packages,
            exchanges: Default::default(),
        }),
        Arc::new(credentials),
        OrchestratorConfig::default(),
    );
    orchestrator.initialize(&service.did).await?;
    Ok(orchestrator)
}
