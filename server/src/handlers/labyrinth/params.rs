//! Request plumbing shared by the Labyrinth handlers: admission, strict query
//! parameters, and the read/write transaction shapes.

use std::collections::BTreeMap;

use axum::http::HeaderMap;
use chrono::{DateTime, Utc};

use crate::handlers::chat::ChatRuntime;
use crate::labyrinth::auth::{self, Admission};
use crate::labyrinth::error::{LabyrinthError, LabyrinthResult};
use crate::labyrinth::repo::{PageReq, TimeRange};
use crate::storage::DbPool;

use super::NSID_PREFIX;

/// Array parameters: repeated keys (`messageIds=a&messageIds=b`).
const ARRAY_PARAMS: &[&str] = &["messageIds"];

/// Strict query parameters: only the declared names (plus `actorDeviceId`,
/// consumed by admission), each at most once unless it is an array.
pub struct Params(BTreeMap<String, Vec<String>>);

impl Params {
    pub fn parse(query: Option<&str>, allowed: &[&str]) -> LabyrinthResult<Self> {
        let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (k, v) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
            if k != "actorDeviceId" && !allowed.contains(&k.as_ref()) {
                return Err(LabyrinthError::invalid(format!("unknown parameter {k}")));
            }
            let values = map.entry(k.clone().into_owned()).or_default();
            if !values.is_empty() && !ARRAY_PARAMS.contains(&k.as_ref()) {
                return Err(LabyrinthError::invalid("a parameter is repeated"));
            }
            values.push(v.into_owned());
        }
        Ok(Self(map))
    }

    pub fn opt(&self, k: &str) -> Option<&str> {
        self.0.get(k).and_then(|v| v.first()).map(String::as_str)
    }

    /// Every value of an array parameter (empty when absent).
    pub fn all(&self, k: &str) -> &[String] {
        self.0.get(k).map(Vec::as_slice).unwrap_or_default()
    }

    /// A boolean parameter (`true` / `false`).
    pub fn flag(&self, k: &str) -> LabyrinthResult<bool> {
        match self.opt(k) {
            None | Some("false") => Ok(false),
            Some("true") => Ok(true),
            Some(_) => Err(LabyrinthError::invalid(format!("{k} is not a boolean"))),
        }
    }

    /// An RFC 3339 datetime parameter.
    pub fn datetime(&self, k: &str) -> LabyrinthResult<Option<DateTime<Utc>>> {
        self.opt(k)
            .map(|v| {
                DateTime::parse_from_rfc3339(v)
                    .map(|at| at.with_timezone(&Utc))
                    .map_err(|_| LabyrinthError::invalid(format!("{k} is not a datetime")))
            })
            .transpose()
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
            reverse: self.flag("reverse")?,
        })
    }

    /// The sender-timestamp window (`fromMs`, `untilMs`) and the server
    /// `receivedAt` window (`since`, `until`) of a list.
    pub fn range(&self) -> LabyrinthResult<TimeRange> {
        const MAX: u64 = (1 << 53) - 1;
        Ok(TimeRange {
            from_ms: self.int("fromMs", MAX)?.map(|v| v as i64),
            until_ms: self.int("untilMs", MAX)?.map(|v| v as i64),
            since: self.datetime("since")?,
            until: self.datetime("until")?,
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
