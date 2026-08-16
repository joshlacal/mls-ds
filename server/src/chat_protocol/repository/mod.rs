//! PostgreSQL boundaries for clean-chat protocol authority.

pub(crate) mod auth;
// `blobs` (Slice 5) owns the migration-3 ciphertext-blob custody surface: the
// dumb row writers plus the closed prepare/upload/bind/delete/expiry transaction
// semantics. Like `delivery`/`inventory`/`welcome`/`ticket` it is unconditionally
// compiled so both the production build and the `#[path]`-including integration
// harness resolve `super::repository::blobs`. Not yet wired to a handler (Task 4).
#[allow(dead_code)]
pub(crate) mod blobs;
#[cfg(not(test))]
pub(crate) mod conversation;
#[cfg(not(test))]
pub(crate) mod core;
#[cfg(not(test))]
#[allow(dead_code)]
pub(crate) mod execution_context;
// `expiry_sweep` is the scheduler-side input for the two work families that
// terminalize on a deadline no client request is guaranteed to reach: due OPEN
// leaf-recovery requests and due PENDING Welcome deliveries. It composes the
// already-sealed welcome-expiry route and the already-built welcome claim; it
// adds no writer and no authority. It depends on `core`/`execution_context`, so
// it carries their `#[cfg(not(test))]` gate; the integration harness `include!`s
// the file directly.
#[cfg(not(test))]
#[allow(dead_code)]
pub(crate) mod expiry_sweep;
// `delivery` and `transition` are the dumb-SQL writers the E2b-2 transition
// executor composes. They are unconditionally compiled (not `#[cfg(not(test))]`)
// so the executor — which is likewise now unconditional — resolves
// `super::repository::{delivery,transition}` under the lib's `cfg(test)` build
// and from the integration harness. Under the production `cfg(not(test))` build
// they were already compiled, so this is behaviour-neutral for production; it
// only additionally makes them available to the test configuration.
pub(crate) mod delivery;
#[cfg(not(test))]
pub(crate) mod entry_read;
#[cfg(not(test))]
pub(crate) mod message_delivery;
// `device_directory` (Task 4 / seal 2b) is the read-only deviceView/
// addressableDevice/ownDeviceView projection surface (key identity + pinned
// capability + live key-package counts) the H1 device handlers need for their
// outputs. Unconditionally compiled so both the production build and the
// `#[path]`-including harness resolve it; self-contained (`chrono`/`sqlx`/`uuid`).
// `#[allow(dead_code)]` until the H1 endpoint handlers (seal 3) call in.
#[allow(dead_code)]
pub(crate) mod device_directory;
pub(crate) mod inventory;
// `key_packages` (Task 4 / OQ-9) is the certified key-package persistence sink
// used by the enrollDevice/replenishKeyPackages handlers. Unconditionally
// compiled so both the production build and the `#[path]`-including integration
// harness resolve `super::repository::key_packages`; self-contained
// (`chrono`/`sha2`/`sqlx`/`uuid`), so the harness includes only this file.
// `#[allow(dead_code)]` until the H1 endpoint handlers (next seal) call in.
#[allow(dead_code)]
pub(crate) mod key_packages;
pub(crate) mod prelude;
#[allow(dead_code)]
pub(crate) mod recovery;
#[cfg(not(test))]
pub(crate) mod relationship;
#[cfg(not(test))]
#[allow(dead_code)]
pub(crate) mod reset;
#[cfg(not(test))]
#[allow(dead_code)]
pub(crate) mod revocation;
#[cfg(not(test))]
pub(crate) mod submit_transition;
pub(crate) mod transition;
#[cfg(not(test))]
#[allow(dead_code)]
pub(crate) mod welcome_terminal;
// `welcome` (Slice 4b) is the welcome-expiry worker claim + recovery-inbox read
// surface. Like `delivery`/`inventory` it is unconditionally compiled so both
// the production build and the `#[path]`-including integration harness resolve
// `super::repository::{delivery,welcome}`.
#[allow(dead_code)]
pub(crate) mod welcome;
// `ticket` (Slice 4c) is the subscription-ticket mint + one-use consume surface
// on the NEW `chat.subscription_tickets` table. Not yet wired to a handler.
#[allow(dead_code)]
pub(crate) mod ticket;
