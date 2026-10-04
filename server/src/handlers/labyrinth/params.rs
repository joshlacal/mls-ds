//! Request plumbing shared by the Labyrinth handlers: admission, strict query
//! parameters, and the read/write transaction shapes.

use std::collections::BTreeMap;

use axum::http::HeaderMap;

use crate::handlers::chat::ChatRuntime;
use crate::labyrinth::auth::{self, Admission};
use crate::labyrinth::error::{LabyrinthError, LabyrinthResult};
use crate::labyrinth::repo::{PageReq, TimeRange};
use crate::storage::DbPool;

use super::NSID_PREFIX;

/// Strict query parameters: each at most once, only the declared names
/// (plus `actorDeviceId`, consumed by admission).
pub struct Params(BTreeMap<String, String>);

impl Params {
    pub fn parse(query: Option<&str>, allowed: &[&str]) -> LabyrinthResult<Self> {
        let mut map = BTreeMap::new();
        for (k, v) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
            if k != "actorDeviceId" && !allowed.contains(&k.as_ref()) {
                return Err(LabyrinthError::invalid(format!("unknown parameter {k}")));
            }
            if map.insert(k.into_owned(), v.into_owned()).is_some() {
                return Err(LabyrinthError::invalid("a parameter is repeated"));
            }
        }
        Ok(Self(map))
    }

    pub fn opt(&self, k: &str) -> Option<&str> {
        self.0.get(k).map(String::as_str)
    }

    pub fn req(&self, k: &str) -> LabyrinthResult<&str> {
        self.opt(k)
            .ok_or_else(|| LabyrinthError::invalid(format!("missing parameter {k}")))
    }

    /// A non-negative integer parameter at most `max`.
    pub fn int(&self, k: &str, max: u64) -> LabyrinthResult<Option<u64>> {
        self.opt(k)
            .map(|v| {
                v.parse::<u64>()
                    .ok()
                    .filter(|n| *n <= max)
                    .ok_or_else(|| LabyrinthError::invalid(format!("{k} is not a valid integer")))
            })
            .transpose()
    }

    pub fn page(&self) -> LabyrinthResult<PageReq> {
        let cursor = self.opt("cursor").map(str::to_owned);
        if cursor
            .as_ref()
            .is_some_and(|c| c.is_empty() || c.len() > 64)
        {
            return Err(LabyrinthError::invalid("cursor is not valid"));
        }
        let limit = self.int("limit", 100)?;
        if limit == Some(0) {
            return Err(LabyrinthError::invalid("limit must be 1..=100"));
        }
        Ok(PageReq {
            cursor,
            limit: limit.map(|l| l as i64),
        })
    }

    pub fn range(&self) -> LabyrinthResult<TimeRange> {
        const MAX: u64 = (1 << 53) - 1;
        Ok(TimeRange {
            from_ms: self.int("fromMs", MAX)?.map(|v| v as i64),
            until_ms: self.int("untilMs", MAX)?.map(|v| v as i64),
        })
    }
}

/// Admit a query for `name` and parse its parameters.
pub async fn admit_query(
    pool: &DbPool,
    runtime: &ChatRuntime,
    name: &str,
    headers: &HeaderMap,
    query: Option<&str>,
    allowed: &[&str],
) -> LabyrinthResult<(Admission, Params)> {
    let nsid = format!("{NSID_PREFIX}{name}");
    let admission =
        auth::admit_query(pool, runtime.cutover_enabled(), &nsid, headers, query).await?;
    let params = Params::parse(query, allowed)?;
    Ok((admission, params))
}

/// Admit a procedure for `name` over this exact body.
pub async fn admit_procedure(
    pool: &DbPool,
    runtime: &ChatRuntime,
    name: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> LabyrinthResult<Admission> {
    let nsid = format!("{NSID_PREFIX}{name}");
    auth::admit_procedure(pool, runtime.cutover_enabled(), &nsid, headers, body).await
}

/// Open a procedure transaction, or return the replayed response.
macro_rules! begin_write {
    ($pool:expr, $admission:expr) => {
        match crate::labyrinth::auth::begin_write($pool, $admission).await? {
            crate::labyrinth::auth::Begun::Replay(bytes) => return Ok(bytes),
            crate::labyrinth::auth::Begun::Fresh(w) => w,
        }
    };
}
pub(super) use begin_write;
