// mlsChat consolidated handlers - PDSS federation
// These are thin adapters that delegate to existing handler logic

// Identity & Devices
pub mod get_key_package_status;
pub mod get_key_packages;
pub mod get_pending_devices;
pub mod list_devices;
pub mod publish_key_packages;
pub mod register_device;

// Conversations & Messaging
pub mod create_convo;
pub mod get_convos;
pub mod get_messages;
pub mod send_message;
pub mod update_cursor;

// Group State
pub mod commit_group_change;
pub mod get_group_state;

// Ephemeral E2EE signals (typing, read receipts, presence)
pub mod send_ephemeral;

// Conversation Management
pub mod get_convo_settings;
pub mod leave_convo;
pub mod update_convo;

// Moderation & Blocks
pub mod blocks;
pub mod get_reports;
pub mod opt_in;
pub mod report;

// Delivery Status
pub mod get_delivery_status;

// Subscriptions
pub mod get_subscription_ticket;

// Federation
pub mod request_failover;

// Re-exports: Identity & Devices
pub use get_key_package_status::get_key_package_status;
pub use get_key_packages::get_key_packages;
pub use get_pending_devices::get_pending_devices;
pub use list_devices::list_devices;
pub use publish_key_packages::publish_key_packages_post;
pub use register_device::register_device_post;

// Re-exports: Conversations & Messaging
pub use create_convo::create_convo;
pub use get_convos::get_convos;
pub use get_messages::get_messages;
pub use send_ephemeral::send_ephemeral;
pub use send_message::send_message;
pub use update_cursor::update_cursor;

// Re-exports: Group State
pub use commit_group_change::commit_group_change;
pub use get_group_state::get_group_state;

// Re-exports: Conversation Management
pub use get_convo_settings::get_convo_settings;
pub use leave_convo::leave_convo;
pub use update_convo::update_convo;

// Re-exports: Moderation & Blocks
pub use blocks::blocks_post;
pub use get_reports::get_reports;
pub use opt_in::opt_in_post;
pub use report::report_post;

// Re-exports: Delivery Status
pub use get_delivery_status::get_delivery_status;

// Re-exports: Subscriptions
pub use get_subscription_ticket::get_subscription_ticket;

// Re-exports: Federation
pub use request_failover::request_failover;
