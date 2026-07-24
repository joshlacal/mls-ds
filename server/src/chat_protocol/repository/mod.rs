//! PostgreSQL boundaries for clean-chat protocol authority.

pub(crate) mod auth;
#[cfg(not(test))]
pub(crate) mod core;
// `delivery` and `transition` are the dumb-SQL writers the E2b-2 transition
// executor composes. They are unconditionally compiled (not `#[cfg(not(test))]`)
// so the executor — which is likewise now unconditional — resolves
// `super::repository::{delivery,transition}` under the lib's `cfg(test)` build
// and from the integration harness. Under the production `cfg(not(test))` build
// they were already compiled, so this is behaviour-neutral for production; it
// only additionally makes them available to the test configuration.
pub(crate) mod delivery;
pub(crate) mod inventory;
#[cfg(not(test))]
pub(crate) mod relationship;
pub(crate) mod transition;
// `welcome` (Slice 4b) is the welcome-expiry worker claim + recovery-inbox read
// surface. Like `delivery`/`inventory` it is unconditionally compiled so both
// the production build and the `#[path]`-including integration harness resolve
// `super::repository::{delivery,welcome}`.
#[allow(dead_code)]
pub(crate) mod welcome;
