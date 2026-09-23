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
        Ok(GatewayResponse {
            status: status.as_u16(),
            content_type: Some("application/json".into()),
            body,
        })
    }

    async fn get_conversations(
        &self,
        _limit: u32,
        _cursor: Option<&str>,
    ) -> ApiResult<catbird_mls::orchestrator::ConversationListPage> {
        Err(outside_projection("get_conversations"))
    }

    async fn get_messages(
        &self,
        _convo_id: &str,
        _cursor: Option<&str>,
        _limit: u32,
        _message_type: Option<&str>,
        _from_epoch: Option<u32>,
        _to_epoch: Option<u32>,
    ) -> ApiResult<(Vec<catbird_mls::orchestrator::IncomingEnvelope>, Option<String>)> {
        Err(outside_projection("get_messages"))
    }

    async fn get_key_packages(
        &self,
        _actor_device_id: &str,
        _dids: &[String],
    ) -> ApiResult<Vec<catbird_mls::orchestrator::KeyPackageRef>> {
        Err(outside_projection("get_key_packages"))
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
        }),
        Arc::new(credentials),
        OrchestratorConfig::default(),
    );
    orchestrator.initialize(&service.did).await?;
    Ok(orchestrator)
}
