use bytes::{Bytes, BytesMut};
use serde::de::DeserializeOwned;
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use tokio::time::Instant;

pub(crate) const DID_DOCUMENT_MAX_BYTES: usize = 256 * 1024;
pub(crate) const PROFILE_OR_DEVICE_MAX_BYTES: usize = 512 * 1024;
pub(crate) const ERROR_RESPONSE_MAX_BYTES: usize = 16 * 1024;
pub(crate) const ORDINARY_DS_CONTROL_MAX_BYTES: usize = 1024 * 1024;

const DECLARED_INITIAL_CAPACITY_MAX_BYTES: usize = 64 * 1024;

/// An explicit response-body limit and the one absolute deadline for the request.
///
/// Callers compute `deadline` before `.send()` and reuse it here. This module
/// enforces only the time remaining while reading and decoding the response body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponseBodyBudget {
    max_bytes: usize,
    deadline: Instant,
}

impl ResponseBodyBudget {
    pub fn new(max_bytes: usize, deadline: Instant) -> Self {
        Self {
            max_bytes,
            deadline,
        }
    }

    pub fn max_bytes(self) -> usize {
        self.max_bytes
    }

    pub fn deadline(self) -> Instant {
        self.deadline
    }
}

pub enum OutboundBodyError {
    DeclaredTooLarge {
        declared_bytes: u64,
        max_bytes: usize,
    },
    StreamedTooLarge {
        observed_at_least_bytes: usize,
        max_bytes: usize,
    },
    LengthOverflow,
    DeadlineExceeded,
    ReadFailed(reqwest::Error),
    InvalidJson(serde_json::Error),
}

impl fmt::Debug for OutboundBodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeclaredTooLarge {
                declared_bytes,
                max_bytes,
            } => formatter
                .debug_struct("OutboundBodyError::DeclaredTooLarge")
                .field("declared_bytes", declared_bytes)
                .field("max_bytes", max_bytes)
                .finish(),
            Self::StreamedTooLarge {
                observed_at_least_bytes,
                max_bytes,
            } => formatter
                .debug_struct("OutboundBodyError::StreamedTooLarge")
                .field("observed_at_least_bytes", observed_at_least_bytes)
                .field("max_bytes", max_bytes)
                .finish(),
            Self::LengthOverflow => formatter.write_str("OutboundBodyError::LengthOverflow"),
            Self::DeadlineExceeded => formatter.write_str("OutboundBodyError::DeadlineExceeded"),
            Self::ReadFailed(_) => formatter.write_str("OutboundBodyError::ReadFailed"),
            Self::InvalidJson(_) => formatter.write_str("OutboundBodyError::InvalidJson"),
        }
    }
}

impl fmt::Display for OutboundBodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeclaredTooLarge {
                declared_bytes,
                max_bytes,
            } => write!(
                formatter,
                "outbound response declared {declared_bytes} bytes, exceeding limit {max_bytes}"
            ),
            Self::StreamedTooLarge {
                observed_at_least_bytes,
                max_bytes,
            } => write!(
                formatter,
                "outbound response reached at least {observed_at_least_bytes} bytes, exceeding limit {max_bytes}"
            ),
            Self::LengthOverflow => {
                formatter.write_str("outbound response length arithmetic overflowed")
            }
            Self::DeadlineExceeded => {
                formatter.write_str("outbound response body deadline exceeded")
            }
            Self::ReadFailed(_) => formatter.write_str("outbound response body read failed"),
            Self::InvalidJson(_) => formatter.write_str("outbound response JSON was invalid"),
        }
    }
}

impl Error for OutboundBodyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ReadFailed(source) => Some(source),
            Self::InvalidJson(source) => Some(source),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SanitizedErrorSummary {
    pub(crate) declared_bytes: Option<u64>,
    pub(crate) observed_at_least_bytes: usize,
    pub(crate) truncated: bool,
}

impl fmt::Display for SanitizedErrorSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "declared_bytes={:?}, observed_at_least_bytes={}, truncated={}",
            self.declared_bytes, self.observed_at_least_bytes, self.truncated
        )
    }
}

/// Collects a response within an explicit limit and the caller's pre-send deadline.
pub async fn collect_bounded(
    mut response: reqwest::Response,
    budget: ResponseBodyBudget,
) -> Result<Bytes, OutboundBodyError> {
    collect_source(&mut response, budget)
        .await
        .map_err(map_collect_error)
}

/// Collects fully within the bound before attempting JSON deserialization.
pub(crate) async fn decode_json_bounded<T: DeserializeOwned>(
    mut response: reqwest::Response,
    budget: ResponseBodyBudget,
) -> Result<T, OutboundBodyError> {
    decode_source(&mut response, budget)
        .await
        .map_err(|error| match error {
            DecodeSourceError::Collect(error) => map_collect_error(error),
            DecodeSourceError::InvalidJson(source) => OutboundBodyError::InvalidJson(source),
        })
}

pub(crate) async fn summarize_error_body(
    mut response: reqwest::Response,
    deadline: Instant,
) -> Result<SanitizedErrorSummary, OutboundBodyError> {
    summarize_source(&mut response, deadline)
        .await
        .map_err(map_collect_error)
}

trait ChunkSource: Unpin {
    type Error;

    fn declared_length(&self) -> Option<u64>;

    fn next_chunk(self: Pin<&mut Self>)
        -> impl Future<Output = Result<Option<Bytes>, Self::Error>>;
}

impl ChunkSource for reqwest::Response {
    type Error = reqwest::Error;

    fn declared_length(&self) -> Option<u64> {
        self.content_length()
    }

    fn next_chunk(
        self: Pin<&mut Self>,
    ) -> impl Future<Output = Result<Option<Bytes>, Self::Error>> {
        self.get_mut().chunk()
    }
}

#[derive(Debug)]
enum CollectError<E> {
    DeclaredTooLarge {
        declared_bytes: u64,
        max_bytes: usize,
    },
    StreamedTooLarge {
        observed_at_least_bytes: usize,
        max_bytes: usize,
    },
    LengthOverflow,
    DeadlineExceeded,
    ReadFailed(E),
}

#[derive(Debug)]
enum DecodeSourceError<E> {
    Collect(CollectError<E>),
    InvalidJson(serde_json::Error),
}

async fn collect_source<S: ChunkSource>(
    source: &mut S,
    budget: ResponseBodyBudget,
) -> Result<Bytes, CollectError<S::Error>> {
    let declared_bytes = source.declared_length();
    if let Some(declared_bytes) = declared_bytes {
        if declared_bytes > budget.max_bytes() as u64 {
            return Err(CollectError::DeclaredTooLarge {
                declared_bytes,
                max_bytes: budget.max_bytes(),
            });
        }
    }

    let initial_capacity = initial_capacity(declared_bytes, budget.max_bytes())?;
    let mut collected = BytesMut::with_capacity(initial_capacity);
    let mut source = Pin::new(source);

    loop {
        let chunk = tokio::time::timeout_at(budget.deadline(), source.as_mut().next_chunk())
            .await
            .map_err(|_| CollectError::DeadlineExceeded)?
            .map_err(CollectError::ReadFailed)?;
        let Some(chunk) = chunk else {
            return Ok(collected.freeze());
        };

        checked_observed_size(collected.len(), chunk.len(), budget.max_bytes())?;
        collected.extend_from_slice(&chunk);
    }
}

fn initial_capacity<E>(
    declared_bytes: Option<u64>,
    max_bytes: usize,
) -> Result<usize, CollectError<E>> {
    match declared_bytes {
        Some(declared_bytes) => {
            Ok(checked_usize_from(declared_bytes)?.min(DECLARED_INITIAL_CAPACITY_MAX_BYTES))
        }
        None => Ok(max_bytes.min(8 * 1024)),
    }
}

fn checked_usize_from<E, T>(value: T) -> Result<usize, CollectError<E>>
where
    usize: TryFrom<T>,
{
    usize::try_from(value).map_err(|_| CollectError::LengthOverflow)
}

fn checked_observed_size<E>(
    current_bytes: usize,
    chunk_bytes: usize,
    max_bytes: usize,
) -> Result<usize, CollectError<E>> {
    let observed_at_least_bytes = current_bytes
        .checked_add(chunk_bytes)
        .ok_or(CollectError::LengthOverflow)?;
    if observed_at_least_bytes > max_bytes {
        return Err(CollectError::StreamedTooLarge {
            observed_at_least_bytes,
            max_bytes,
        });
    }
    Ok(observed_at_least_bytes)
}

async fn decode_source<T: DeserializeOwned, S: ChunkSource>(
    source: &mut S,
    budget: ResponseBodyBudget,
) -> Result<T, DecodeSourceError<S::Error>> {
    let bytes = collect_source(source, budget)
        .await
        .map_err(DecodeSourceError::Collect)?;
    if Instant::now() >= budget.deadline() {
        return Err(DecodeSourceError::Collect(CollectError::DeadlineExceeded));
    }
    let value = serde_json::from_slice(&bytes).map_err(DecodeSourceError::InvalidJson)?;
    if Instant::now() >= budget.deadline() {
        return Err(DecodeSourceError::Collect(CollectError::DeadlineExceeded));
    }
    Ok(value)
}

async fn summarize_source<S: ChunkSource>(
    source: &mut S,
    deadline: Instant,
) -> Result<SanitizedErrorSummary, CollectError<S::Error>> {
    let declared_bytes = source.declared_length();
    let budget = ResponseBodyBudget::new(ERROR_RESPONSE_MAX_BYTES, deadline);
    match collect_source(source, budget).await {
        Ok(bytes) => Ok(SanitizedErrorSummary {
            declared_bytes,
            observed_at_least_bytes: bytes.len(),
            truncated: false,
        }),
        Err(CollectError::DeclaredTooLarge { declared_bytes, .. }) => Ok(SanitizedErrorSummary {
            declared_bytes: Some(declared_bytes),
            observed_at_least_bytes: usize::try_from(declared_bytes).unwrap_or(usize::MAX),
            truncated: true,
        }),
        Err(CollectError::StreamedTooLarge {
            observed_at_least_bytes,
            ..
        }) => Ok(SanitizedErrorSummary {
            declared_bytes,
            observed_at_least_bytes,
            truncated: true,
        }),
        Err(error) => Err(error),
    }
}

fn map_collect_error(error: CollectError<reqwest::Error>) -> OutboundBodyError {
    match error {
        CollectError::DeclaredTooLarge {
            declared_bytes,
            max_bytes,
        } => OutboundBodyError::DeclaredTooLarge {
            declared_bytes,
            max_bytes,
        },
        CollectError::StreamedTooLarge {
            observed_at_least_bytes,
            max_bytes,
        } => OutboundBodyError::StreamedTooLarge {
            observed_at_least_bytes,
            max_bytes,
        },
        CollectError::LengthOverflow => OutboundBodyError::LengthOverflow,
        CollectError::DeadlineExceeded => OutboundBodyError::DeadlineExceeded,
        CollectError::ReadFailed(source) => OutboundBodyError::ReadFailed(source),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::collections::VecDeque;
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    #[derive(Debug)]
    struct FakeBody<E> {
        declared_bytes: Option<u64>,
        chunks: VecDeque<Result<Bytes, E>>,
        polls: usize,
        delay: Duration,
    }

    impl<E> FakeBody<E> {
        fn new(declared_bytes: Option<u64>, chunks: Vec<Result<Bytes, E>>) -> Self {
            Self {
                declared_bytes,
                chunks: chunks.into(),
                polls: 0,
                delay: Duration::ZERO,
            }
        }

        fn delayed(mut self, delay: Duration) -> Self {
            self.delay = delay;
            self
        }
    }

    impl<E: Unpin> ChunkSource for FakeBody<E> {
        type Error = E;

        fn declared_length(&self) -> Option<u64> {
            self.declared_bytes
        }

        async fn next_chunk(self: Pin<&mut Self>) -> Result<Option<Bytes>, Self::Error> {
            let source = self.get_mut();
            source.polls += 1;
            tokio::time::sleep(source.delay).await;
            source.chunks.pop_front().transpose()
        }
    }

    fn budget(max_bytes: usize, after: Duration) -> ResponseBodyBudget {
        ResponseBodyBudget::new(max_bytes, tokio::time::Instant::now() + after)
    }

    #[test]
    fn profile_limits_are_locked() {
        assert_eq!(DID_DOCUMENT_MAX_BYTES, 256 * 1024);
        assert_eq!(PROFILE_OR_DEVICE_MAX_BYTES, 512 * 1024);
        assert_eq!(ERROR_RESPONSE_MAX_BYTES, 16 * 1024);
        assert_eq!(ORDINARY_DS_CONTROL_MAX_BYTES, 1024 * 1024);
    }

    #[test]
    fn budget_has_no_implicit_default_and_preserves_explicit_values() {
        trait AmbiguousIfDefault<Marker> {
            fn marker() {}
        }
        impl<T: ?Sized> AmbiguousIfDefault<()> for T {}
        impl<T: Default> AmbiguousIfDefault<u8> for T {}

        let _ = <ResponseBodyBudget as AmbiguousIfDefault<_>>::marker;
        let deadline = tokio::time::Instant::now();
        let budget = ResponseBodyBudget::new(0, deadline);
        assert_eq!(budget.max_bytes(), 0);
        assert_eq!(budget.deadline(), deadline);
    }

    #[tokio::test]
    async fn declared_oversize_rejects_without_polling() {
        let mut body = FakeBody::<Infallible>::new(Some(5), vec![Ok(Bytes::from_static(b"x"))]);
        let result = collect_source(&mut body, budget(4, Duration::from_secs(1))).await;

        assert!(matches!(
            result,
            Err(CollectError::DeclaredTooLarge {
                declared_bytes: 5,
                max_bytes: 4
            })
        ));
        assert_eq!(body.polls, 0);
    }

    #[tokio::test]
    async fn crossing_chunk_rejects_before_extension() {
        let mut body = FakeBody::<Infallible>::new(
            None,
            vec![
                Ok(Bytes::from_static(b"1234")),
                Ok(Bytes::from_static(b"56")),
            ],
        );
        let result = collect_source(&mut body, budget(5, Duration::from_secs(1))).await;

        assert!(matches!(
            result,
            Err(CollectError::StreamedTooLarge {
                observed_at_least_bytes: 6,
                max_bytes: 5
            })
        ));
    }

    #[tokio::test]
    async fn exact_limits_and_zero_cap_are_enforced() {
        let mut exact_declared =
            FakeBody::<Infallible>::new(Some(4), vec![Ok(Bytes::from_static(b"1234"))]);
        assert_eq!(
            collect_source(&mut exact_declared, budget(4, Duration::from_secs(1)))
                .await
                .unwrap(),
            Bytes::from_static(b"1234")
        );

        let mut exact_streamed = FakeBody::<Infallible>::new(
            None,
            vec![Ok(Bytes::from_static(b"12")), Ok(Bytes::from_static(b"34"))],
        );
        assert_eq!(
            collect_source(&mut exact_streamed, budget(4, Duration::from_secs(1)))
                .await
                .unwrap(),
            Bytes::from_static(b"1234")
        );

        let mut empty = FakeBody::<Infallible>::new(None, vec![]);
        assert!(
            collect_source(&mut empty, budget(0, Duration::from_secs(1)))
                .await
                .unwrap()
                .is_empty()
        );

        let mut one = FakeBody::<Infallible>::new(None, vec![Ok(Bytes::from_static(b"x"))]);
        assert!(matches!(
            collect_source(&mut one, budget(0, Duration::from_secs(1))).await,
            Err(CollectError::StreamedTooLarge {
                observed_at_least_bytes: 1,
                max_bytes: 0
            })
        ));
    }

    #[test]
    fn arithmetic_overflow_is_detected_without_allocation() {
        assert!(matches!(
            checked_observed_size(usize::MAX, 1, usize::MAX),
            Err(CollectError::<Infallible>::LengthOverflow)
        ));
    }

    #[test]
    fn initial_capacity_is_bounded_without_changing_body_limit() {
        assert_eq!(
            initial_capacity::<Infallible>(
                Some(ORDINARY_DS_CONTROL_MAX_BYTES as u64),
                ORDINARY_DS_CONTROL_MAX_BYTES,
            )
            .unwrap(),
            64 * 1024
        );
        assert_eq!(
            initial_capacity::<Infallible>(Some(1234), ORDINARY_DS_CONTROL_MAX_BYTES).unwrap(),
            1234
        );
        assert_eq!(initial_capacity::<Infallible>(None, 4096).unwrap(), 4096);
        assert_eq!(
            initial_capacity::<Infallible>(None, ORDINARY_DS_CONTROL_MAX_BYTES).unwrap(),
            8 * 1024
        );
        assert!(matches!(
            checked_usize_from::<Infallible, _>(u128::MAX),
            Err(CollectError::LengthOverflow)
        ));
    }

    #[tokio::test]
    async fn slow_trickle_uses_one_absolute_deadline() {
        let mut body = FakeBody::<Infallible>::new(
            None,
            vec![
                Ok(Bytes::from_static(b"a")),
                Ok(Bytes::from_static(b"b")),
                Ok(Bytes::from_static(b"c")),
            ],
        )
        .delayed(Duration::from_millis(40));

        assert!(matches!(
            collect_source(&mut body, budget(3, Duration::from_millis(90))).await,
            Err(CollectError::DeadlineExceeded)
        ));
        assert_eq!(body.polls, 3);
    }

    #[tokio::test]
    async fn malformed_json_is_parsed_only_after_bounded_collection() {
        let malformed = Bytes::from_static(b"{not-json-and-too-long}");
        let mut oversized = FakeBody::<Infallible>::new(None, vec![Ok(malformed.clone())]);
        assert!(matches!(
            decode_source::<serde_json::Value, _>(
                &mut oversized,
                budget(4, Duration::from_secs(1))
            )
            .await,
            Err(DecodeSourceError::Collect(
                CollectError::StreamedTooLarge { .. }
            ))
        ));

        let mut bounded = FakeBody::<Infallible>::new(None, vec![Ok(malformed.clone())]);
        assert!(matches!(
            decode_source::<serde_json::Value, _>(
                &mut bounded,
                budget(malformed.len(), Duration::from_secs(1))
            )
            .await,
            Err(DecodeSourceError::InvalidJson(_))
        ));
    }

    static SLOW_DESERIALIZE_STARTED: AtomicBool = AtomicBool::new(false);

    struct SlowJson;

    impl<'de> serde::Deserialize<'de> for SlowJson {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let _: serde_json::Value = serde::Deserialize::deserialize(deserializer)?;
            SLOW_DESERIALIZE_STARTED.store(true, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(200));
            Ok(Self)
        }
    }

    #[tokio::test]
    async fn json_parse_completing_after_deadline_cannot_succeed() {
        SLOW_DESERIALIZE_STARTED.store(false, Ordering::SeqCst);
        let mut source = FakeBody::<Infallible>::new(Some(2), vec![Ok(Bytes::from_static(b"{}"))]);

        assert!(matches!(
            decode_source::<SlowJson, _>(&mut source, budget(2, Duration::from_millis(100)),).await,
            Err(DecodeSourceError::Collect(CollectError::DeadlineExceeded))
        ));
        assert!(SLOW_DESERIALIZE_STARTED.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn sanitized_summary_formats_never_include_body_sentinels() {
        let bearer = "Bearer UNIQUE-SECRET-BEARER";
        let cookie = "Cookie=UNIQUE-SECRET-COOKIE";
        let body = Bytes::from(format!("{bearer}; {cookie}"));
        let mut source = FakeBody::<Infallible>::new(Some(body.len() as u64), vec![Ok(body)]);
        let summary = summarize_source(
            &mut source,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap();

        for rendered in [format!("{summary:?}"), format!("{summary}")] {
            assert!(!rendered.contains(bearer));
            assert!(!rendered.contains(cookie));
        }
    }

    #[tokio::test]
    async fn declared_error_oversize_is_truncated_without_polling() {
        let mut source = FakeBody::<Infallible>::new(
            Some(ERROR_RESPONSE_MAX_BYTES as u64 + 1),
            vec![Ok(Bytes::from_static(b"secret"))],
        );
        let summary = summarize_source(
            &mut source,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap();

        assert_eq!(source.polls, 0);
        assert_eq!(
            summary,
            SanitizedErrorSummary {
                declared_bytes: Some(ERROR_RESPONSE_MAX_BYTES as u64 + 1),
                observed_at_least_bytes: ERROR_RESPONSE_MAX_BYTES + 1,
                truncated: true,
            }
        );
    }

    #[tokio::test]
    async fn chunked_error_oversize_stops_at_first_crossing_chunk() {
        let mut source = FakeBody::<Infallible>::new(
            None,
            vec![
                Ok(Bytes::from(vec![0; ERROR_RESPONSE_MAX_BYTES])),
                Ok(Bytes::from_static(b"cross")),
                Ok(Bytes::from_static(b"must-not-poll")),
            ],
        );
        let summary = summarize_source(
            &mut source,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap();

        assert_eq!(source.polls, 2);
        assert_eq!(summary.declared_bytes, None);
        assert_eq!(
            summary.observed_at_least_bytes,
            ERROR_RESPONSE_MAX_BYTES + 5
        );
        assert!(summary.truncated);
    }

    #[derive(Debug, Eq, PartialEq)]
    struct PrematureClose;

    #[tokio::test]
    async fn premature_close_maps_to_read_failed() {
        let mut source = FakeBody::new(
            None,
            vec![Ok(Bytes::from_static(b"partial")), Err(PrematureClose)],
        );

        assert!(matches!(
            collect_source(&mut source, budget(32, Duration::from_secs(1))).await,
            Err(CollectError::ReadFailed(PrematureClose))
        ));
    }

    #[tokio::test]
    async fn outbound_error_debug_is_exact_and_source_content_free() {
        assert_eq!(
            format!(
                "{:?}",
                OutboundBodyError::DeclaredTooLarge {
                    declared_bytes: 9,
                    max_bytes: 8,
                }
            ),
            "OutboundBodyError::DeclaredTooLarge { declared_bytes: 9, max_bytes: 8 }"
        );
        assert_eq!(
            format!(
                "{:?}",
                OutboundBodyError::StreamedTooLarge {
                    observed_at_least_bytes: 9,
                    max_bytes: 8,
                }
            ),
            "OutboundBodyError::StreamedTooLarge { observed_at_least_bytes: 9, max_bytes: 8 }"
        );
        assert_eq!(
            format!("{:?}", OutboundBodyError::LengthOverflow),
            "OutboundBodyError::LengthOverflow"
        );
        assert_eq!(
            format!("{:?}", OutboundBodyError::DeadlineExceeded),
            "OutboundBodyError::DeadlineExceeded"
        );

        let url_sentinel = "UNIQUE-SECRET-URL-QUERY";
        let read_source = reqwest::Client::new()
            .get(format!(
                "ftp://example.invalid/private?token={url_sentinel}"
            ))
            .send()
            .await
            .unwrap_err();
        assert!(format!("{read_source:?}").contains(url_sentinel));
        let read_error = OutboundBodyError::ReadFailed(read_source);
        assert_eq!(format!("{read_error:?}"), "OutboundBodyError::ReadFailed");
        assert!(!format!("{read_error}").contains(url_sentinel));
        assert!(!format!("{read_error:?}").contains(url_sentinel));
        assert!(std::error::Error::source(&read_error).is_some());

        let body_sentinel = "UNIQUE-SECRET-JSON-BODY";
        let json_source = <serde_json::Error as serde::de::Error>::custom(body_sentinel.to_owned());
        assert!(json_source.to_string().contains(body_sentinel));
        let json_error = OutboundBodyError::InvalidJson(json_source);
        assert_eq!(format!("{json_error:?}"), "OutboundBodyError::InvalidJson");
        assert!(!format!("{json_error}").contains(body_sentinel));
        assert!(!format!("{json_error:?}").contains(body_sentinel));
        assert!(std::error::Error::source(&json_error).is_some());
    }
}
