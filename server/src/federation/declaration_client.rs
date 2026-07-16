use moka::future::Cache;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error};

use super::errors::FederationError;
use super::resolver::DsResolver;
use crate::util::outbound_body::{
    decode_json_bounded, OutboundBodyError, ResponseBodyBudget, PROFILE_OR_DEVICE_MAX_BYTES,
};

const OUTBOUND_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_DEVICE_RECORDS: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub uri: String,
    pub cid: String,
    pub value: DeviceRecordValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecordValue {
    #[serde(rename = "$type")]
    pub record_type: Option<String>,
    #[serde(rename = "mlsSignaturePublicKey")]
    pub mls_signature_public_key: Option<BytesWrapper>,
    pub algorithm: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BytesWrapper {
    #[serde(rename = "$bytes")]
    pub bytes: String,
}

/// A simple client to fetch and cache user device records from their PDS.
#[derive(Clone)]
pub struct DeviceRecordClient {
    http: Client,
    resolver: Arc<DsResolver>,
    /// Map DID -> List of device records
    cache: Cache<String, Vec<DeviceRecord>>,
}

impl DeviceRecordClient {
    pub fn new(http: Client, resolver: Arc<DsResolver>) -> Self {
        // Short, small cache: 5 minutes TTL, max 1000 users
        let cache = Cache::builder()
            .time_to_live(Duration::from_secs(300))
            .max_capacity(1000)
            .build();

        Self {
            http,
            resolver,
            cache,
        }
    }

    /// Fetch device records for a DID.
    ///
    /// This method:
    /// 1. Checks the local short-term cache.
    /// 2. If missing, resolves the user's PDS via DsResolver.
    /// 3. Queries com.atproto.repo.listRecords on the PDS.
    /// 4. Caches and returns the records.
    pub async fn fetch_device_records(
        &self,
        did: &str,
    ) -> Result<Vec<DeviceRecord>, FederationError> {
        if let Some(cached) = self.cache.get(did).await {
            return Ok(cached);
        }

        let records = self.fetch_from_pds(did).await?;

        // Cache even if empty (user might not have registered any devices yet)
        self.cache.insert(did.to_string(), records.clone()).await;

        Ok(records)
    }

    async fn fetch_from_pds(&self, did: &str) -> Result<Vec<DeviceRecord>, FederationError> {
        let pds_endpoint = self.resolver.resolve_did_to_pds(did).await?;

        self.fetch_from_pds_endpoint(did, &pds_endpoint, OUTBOUND_REQUEST_TIMEOUT)
            .await
    }

    async fn fetch_from_pds_endpoint(
        &self,
        did: &str,
        pds_endpoint: &str,
        timeout: Duration,
    ) -> Result<Vec<DeviceRecord>, FederationError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| FederationError::ResolutionFailed {
                did: did.to_string(),
                reason: "HTTP request deadline overflow".to_string(),
            })?;

        // com.atproto.repo.listRecords
        // Using "blue.catbird.mlsChat.device" collection
        let url = format!(
            "{}/xrpc/com.atproto.repo.listRecords?repo={}&collection=blue.catbird.mlsChat.device&limit=100",
            pds_endpoint,
            urlencoding::encode(did)
        );

        debug!("Fetching device records for {} from {}", did, url);

        let resp = self
            .send_before_deadline(self.http.get(&url), deadline, did)
            .await?;

        if !resp.status().is_success() {
            return Err(FederationError::ResolutionFailed {
                did: did.to_string(),
                reason: format!("PDS returned status {}", resp.status()),
            });
        }

        let body: serde_json::Value = decode_json_bounded(
            resp,
            ResponseBodyBudget::new(PROFILE_OR_DEVICE_MAX_BYTES, deadline),
        )
        .await
        .map_err(|error| Self::response_decode_error(did, error))?;

        // Extract records array
        let records_json = body
            .get("records")
            .and_then(|v| v.as_array())
            .ok_or_else(|| FederationError::ResolutionFailed {
                did: did.to_string(),
                reason: "No 'records' field in listRecords response".to_string(),
            })?;

        if records_json.len() > MAX_DEVICE_RECORDS {
            return Err(FederationError::ResolutionFailed {
                did: did.to_string(),
                reason: format!("PDS returned more than {MAX_DEVICE_RECORDS} device records"),
            });
        }

        let mut records = Vec::new();
        for record_json in records_json {
            match serde_json::from_value::<DeviceRecord>(record_json.clone()) {
                Ok(record) => records.push(record),
                Err(e) => {
                    // Log but don't fail entire fetch
                    error!("Failed to parse device record for {}: {}", did, e);
                }
            }
        }

        Ok(records)
    }

    /// Fetch the current chat policy for a user from their PDS.
    ///
    /// Reads the single `blue.catbird.mlsChat.policy/self` record via
    /// `com.atproto.repo.getRecord`.
    pub async fn get_chat_policy(&self, did: &str) -> Result<MLSChatPolicy, FederationError> {
        let pds_endpoint = self.resolver.resolve_did_to_pds(did).await?;

        self.get_chat_policy_from_endpoint(did, &pds_endpoint, OUTBOUND_REQUEST_TIMEOUT)
            .await
    }

    async fn get_chat_policy_from_endpoint(
        &self,
        did: &str,
        pds_endpoint: &str,
        timeout: Duration,
    ) -> Result<MLSChatPolicy, FederationError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| FederationError::ResolutionFailed {
                did: did.to_string(),
                reason: "HTTP request deadline overflow".to_string(),
            })?;

        let url = format!(
            "{}/xrpc/com.atproto.repo.getRecord?repo={}&collection=blue.catbird.mlsChat.policy&rkey=self",
            pds_endpoint,
            urlencoding::encode(did)
        );

        debug!("Fetching chat policy for {} from {}", did, url);

        let resp = self
            .send_before_deadline(self.http.get(&url), deadline, did)
            .await?;

        if !resp.status().is_success() {
            // 400/404 is expected if user hasn't set a policy yet
            debug!(
                "No policy record for {} (status {}), returning defaults",
                did,
                resp.status()
            );
            return Ok(MLSChatPolicy::default());
        }

        let body: serde_json::Value = decode_json_bounded(
            resp,
            ResponseBodyBudget::new(PROFILE_OR_DEVICE_MAX_BYTES, deadline),
        )
        .await
        .map_err(|error| Self::response_decode_error(did, error))?;

        // The record value is in body.value
        let value = body.get("value").unwrap_or(&body);

        let policy = MLSChatPolicy {
            allow_followers_bypass: value.get("allowFollowersBypass").and_then(|v| v.as_bool()),
            allow_following_bypass: value.get("allowFollowingBypass").and_then(|v| v.as_bool()),
            who_can_message_me: value
                .get("whoCanMessageMe")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            auto_expire_days: value
                .get("autoExpireDays")
                .and_then(|v| v.as_i64())
                .map(|v| v as i32),
        };

        Ok(policy)
    }

    async fn send_before_deadline(
        &self,
        request: reqwest::RequestBuilder,
        deadline: tokio::time::Instant,
        did: &str,
    ) -> Result<reqwest::Response, FederationError> {
        tokio::time::timeout_at(deadline, request.send())
            .await
            .map_err(|_| FederationError::ResolutionFailed {
                did: did.to_string(),
                reason: "HTTP request failed: outbound request deadline exceeded".to_string(),
            })?
            .map_err(|error| FederationError::ResolutionFailed {
                did: did.to_string(),
                reason: format!("HTTP request failed: {error}"),
            })
    }

    fn response_decode_error(did: &str, error: OutboundBodyError) -> FederationError {
        let category = match error {
            OutboundBodyError::InvalidJson(_) => "Invalid JSON response",
            _ => "Response body rejected",
        };
        FederationError::ResolutionFailed {
            did: did.to_string(),
            reason: format!("{category}: {error}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MLSChatPolicy {
    pub allow_followers_bypass: Option<bool>,
    pub allow_following_bypass: Option<bool>,
    pub who_can_message_me: Option<String>,
    pub auto_expire_days: Option<i32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Response, StatusCode},
        routing::get,
        Router,
    };
    use bytes::Bytes;
    use futures::stream;
    use serde_json::{json, Value};
    use sqlx::postgres::PgPoolOptions;
    use std::convert::Infallible;
    use tokio::net::TcpListener;

    const TEST_DID: &str = "did:example:alice";

    fn device_record(index: usize) -> Value {
        json!({
            "uri": format!("at://{TEST_DID}/blue.catbird.mlsChat.device/{index}"),
            "cid": format!("cid-{index}"),
            "value": {
                "$type": "blue.catbird.mlsChat.device",
                "mlsSignaturePublicKey": { "$bytes": "AQID" },
                "algorithm": "ed25519",
                "createdAt": "2026-07-16T00:00:00Z"
            }
        })
    }

    async fn spawn_pds(router: Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        format!("http://{address}")
    }

    fn client() -> DeviceRecordClient {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1/unused")
            .unwrap();
        let http = Client::new();
        let resolver = Arc::new(DsResolver::new(
            pool,
            http.clone(),
            TEST_DID.to_string(),
            "https://unused.invalid".to_string(),
            None,
            300,
        ));
        DeviceRecordClient::new(http, resolver)
    }

    fn resolution_reason(error: FederationError) -> String {
        match error {
            FederationError::ResolutionFailed { did, reason } => {
                assert_eq!(did, TEST_DID);
                reason
            }
            other => panic!("expected ResolutionFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn device_list_accepts_100_records_and_rejects_101() {
        async fn list_records() -> Response<Body> {
            let count = 101;
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(
                    json!({
                        "records": (0..count).map(device_record).collect::<Vec<_>>()
                    })
                    .to_string(),
                ))
                .unwrap()
        }

        let endpoint =
            spawn_pds(Router::new().route("/xrpc/com.atproto.repo.listRecords", get(list_records)))
                .await;
        let error = client()
            .fetch_from_pds_endpoint(TEST_DID, &endpoint, Duration::from_secs(10))
            .await
            .unwrap_err();

        assert!(resolution_reason(error).contains("more than 100"));

        async fn exact_list() -> Response<Body> {
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(
                    json!({
                        "records": (0..100).map(device_record).collect::<Vec<_>>()
                    })
                    .to_string(),
                ))
                .unwrap()
        }
        let endpoint =
            spawn_pds(Router::new().route("/xrpc/com.atproto.repo.listRecords", get(exact_list)))
                .await;
        assert_eq!(
            client()
                .fetch_from_pds_endpoint(TEST_DID, &endpoint, Duration::from_secs(10))
                .await
                .unwrap()
                .len(),
            100
        );
    }

    #[tokio::test]
    async fn device_list_rejects_declared_and_chunked_oversize_bodies() {
        async fn declared() -> Response<Body> {
            let body = vec![b' '; crate::util::outbound_body::PROFILE_OR_DEVICE_MAX_BYTES + 1];
            Response::builder()
                .status(StatusCode::OK)
                .header("content-length", body.len().to_string())
                .body(Body::from(body))
                .unwrap()
        }
        let endpoint =
            spawn_pds(Router::new().route("/xrpc/com.atproto.repo.listRecords", get(declared)))
                .await;
        let reason = resolution_reason(
            client()
                .fetch_from_pds_endpoint(TEST_DID, &endpoint, Duration::from_secs(10))
                .await
                .unwrap_err(),
        );
        assert!(reason.contains("exceeding limit"), "{reason}");
        assert!(!reason.contains("Invalid JSON response"), "{reason}");

        async fn chunked() -> Response<Body> {
            let chunks = stream::iter([
                Ok::<_, Infallible>(Bytes::from(vec![
                    b' ';
                    crate::util::outbound_body::PROFILE_OR_DEVICE_MAX_BYTES
                ])),
                Ok(Bytes::from_static(b"x")),
            ]);
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from_stream(chunks))
                .unwrap()
        }
        let endpoint =
            spawn_pds(Router::new().route("/xrpc/com.atproto.repo.listRecords", get(chunked)))
                .await;
        let reason = resolution_reason(
            client()
                .fetch_from_pds_endpoint(TEST_DID, &endpoint, Duration::from_secs(10))
                .await
                .unwrap_err(),
        );
        assert!(reason.contains("exceeding limit"), "{reason}");
        assert!(!reason.contains("Invalid JSON response"), "{reason}");
    }

    #[tokio::test]
    async fn device_malformed_json_and_non_success_keep_resolution_failed_mapping() {
        async fn malformed() -> Response<Body> {
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(r#"{"secret":"do-not-log","#))
                .unwrap()
        }
        let endpoint =
            spawn_pds(Router::new().route("/xrpc/com.atproto.repo.listRecords", get(malformed)))
                .await;
        let reason = resolution_reason(
            client()
                .fetch_from_pds_endpoint(TEST_DID, &endpoint, Duration::from_secs(10))
                .await
                .unwrap_err(),
        );
        assert_eq!(
            reason,
            "Invalid JSON response: outbound response JSON was invalid"
        );
        assert!(!reason.contains("do-not-log"));

        async fn unavailable() -> StatusCode {
            StatusCode::SERVICE_UNAVAILABLE
        }
        let endpoint =
            spawn_pds(Router::new().route("/xrpc/com.atproto.repo.listRecords", get(unavailable)))
                .await;
        let reason = resolution_reason(
            client()
                .fetch_from_pds_endpoint(TEST_DID, &endpoint, Duration::from_secs(10))
                .await
                .unwrap_err(),
        );
        assert_eq!(reason, "PDS returned status 503 Service Unavailable");
    }

    #[tokio::test]
    async fn policy_non_success_returns_default_without_collecting_body() {
        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::NOT_FOUND,
            StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            let endpoint = spawn_pds(Router::new().route(
                "/xrpc/com.atproto.repo.getRecord",
                get(move || async move {
                    Response::builder()
                        .status(status)
                        .body(Body::from_stream(stream::pending::<
                            Result<Bytes, Infallible>,
                        >()))
                        .unwrap()
                }),
            ))
            .await;
            let policy = tokio::time::timeout(
                Duration::from_millis(250),
                client().get_chat_policy_from_endpoint(
                    TEST_DID,
                    &endpoint,
                    Duration::from_secs(10),
                ),
            )
            .await
            .expect("non-success policy response must not collect its body")
            .unwrap();

            assert!(policy.allow_followers_bypass.is_none());
            assert!(policy.allow_following_bypass.is_none());
            assert!(policy.who_can_message_me.is_none());
            assert!(policy.auto_expire_days.is_none());
        }
    }

    #[tokio::test]
    async fn policy_success_rejects_declared_and_chunked_oversize_bodies() {
        async fn declared() -> Response<Body> {
            let body = vec![b' '; crate::util::outbound_body::PROFILE_OR_DEVICE_MAX_BYTES + 1];
            Response::builder()
                .status(StatusCode::OK)
                .header("content-length", body.len().to_string())
                .body(Body::from(body))
                .unwrap()
        }
        let endpoint =
            spawn_pds(Router::new().route("/xrpc/com.atproto.repo.getRecord", get(declared))).await;
        let reason = resolution_reason(
            client()
                .get_chat_policy_from_endpoint(TEST_DID, &endpoint, Duration::from_secs(10))
                .await
                .unwrap_err(),
        );
        assert!(reason.contains("exceeding limit"), "{reason}");
        assert!(!reason.contains("Invalid JSON response"), "{reason}");

        async fn chunked() -> Response<Body> {
            let chunks = stream::iter([
                Ok::<_, Infallible>(Bytes::from(vec![
                    b' ';
                    crate::util::outbound_body::PROFILE_OR_DEVICE_MAX_BYTES
                ])),
                Ok(Bytes::from_static(b"x")),
            ]);
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from_stream(chunks))
                .unwrap()
        }
        let endpoint =
            spawn_pds(Router::new().route("/xrpc/com.atproto.repo.getRecord", get(chunked))).await;
        let reason = resolution_reason(
            client()
                .get_chat_policy_from_endpoint(TEST_DID, &endpoint, Duration::from_secs(10))
                .await
                .unwrap_err(),
        );
        assert!(reason.contains("exceeding limit"), "{reason}");
        assert!(!reason.contains("Invalid JSON response"), "{reason}");
    }

    #[tokio::test]
    async fn slow_headers_and_body_share_one_pre_send_deadline() {
        async fn slow_response() -> Response<Body> {
            tokio::time::sleep(Duration::from_millis(80)).await;
            let body = stream::once(async {
                tokio::time::sleep(Duration::from_millis(80)).await;
                Ok::<_, Infallible>(Bytes::from_static(br#"{"records":[]}"#))
            });
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from_stream(body))
                .unwrap()
        }
        let endpoint = spawn_pds(
            Router::new().route("/xrpc/com.atproto.repo.listRecords", get(slow_response)),
        )
        .await;

        let reason = resolution_reason(
            client()
                .fetch_from_pds_endpoint(TEST_DID, &endpoint, Duration::from_millis(120))
                .await
                .unwrap_err(),
        );

        assert!(reason.contains("deadline exceeded"), "{reason}");
        assert!(!reason.contains("Invalid JSON response"), "{reason}");
    }

    #[test]
    fn success_paths_have_no_unbounded_response_collectors() {
        let source = include_str!("declaration_client.rs");
        for suffix in [".json()", ".bytes()", ".text()"] {
            let needle = ["resp", suffix].concat();
            assert!(!source.contains(&needle), "found {needle}");
        }
    }
}
