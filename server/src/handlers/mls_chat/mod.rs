// mlsChat consolidated handlers - PDSS federation
// These are thin adapters that delegate to existing handler logic

// Identity & Devices
pub mod get_key_package_status;
pub mod get_key_packages;
pub mod get_pending_devices;
pub mod invalidate_key_package;
pub mod list_devices;
pub mod publish_key_packages;
pub mod reconcile_key_packages;
pub mod register_device;
pub mod register_device_token;
pub mod reissue_welcome;
pub mod reissue_welcome_respond;
pub mod remove_device;

// Conversations & Messaging
pub mod create_convo;
pub mod get_convos;
pub mod get_messages;
pub mod send_message;
pub mod update_cursor;

// Group State
pub mod bootstrap_reset_group;
pub mod commit_group_change;
pub mod commit_inspect;
pub mod get_group_health;
pub mod get_group_state;
pub mod report_recovery_failure;
pub mod reset_group;

// Conversation Management
pub mod get_convo_settings;
pub mod leave_convo;
pub mod update_convo;

// Moderation & Blocks
pub mod check_blocks;
pub mod get_block_status;
pub mod opt_in;
pub mod report_spam;

// Delivery Status
pub mod get_delivery_status;

// Blob Storage
pub mod delete_blob;
pub mod get_blob;
pub mod get_blob_usage;
pub mod get_group_metadata_blob;
pub mod put_group_metadata_blob;
pub mod upload_blob;

// Subscriptions
pub mod get_subscription_ticket;

// Federation
pub mod request_failover;

// Re-exports: Identity & Devices
pub use get_key_package_status::get_key_package_status;
pub use get_key_packages::get_key_packages;
pub use get_pending_devices::get_pending_devices;
pub use invalidate_key_package::invalidate_key_package;
pub use list_devices::list_devices;
pub use publish_key_packages::publish_key_packages_post;
pub use reconcile_key_packages::reconcile_key_packages;
pub use register_device::register_device_post;
pub use register_device_token::register_device_token;
pub use reissue_welcome::reissue_welcome;
pub use reissue_welcome_respond::reissue_welcome_respond;
pub use remove_device::remove_device;

// Re-exports: Conversations & Messaging
pub use create_convo::create_convo;
pub use get_convos::get_convos;
pub use get_messages::get_messages;
pub use send_message::send_message;
pub use update_cursor::update_cursor;

// Re-exports: Group State
pub use commit_group_change::commit_group_change;
pub use get_group_health::get_group_health;
pub use get_group_state::get_group_state;
pub use report_recovery_failure::report_recovery_failure;
pub use reset_group::reset_group;

// Re-exports: Conversation Management
pub use get_convo_settings::get_convo_settings;
pub use leave_convo::leave_convo;
pub use update_convo::update_convo;

// Re-exports: Moderation & Blocks
pub use opt_in::opt_in_post;
pub use report_spam::report_spam_post;

// Re-exports: Delivery Status
pub use get_delivery_status::get_delivery_status;

// Re-exports: Blob Storage
pub use delete_blob::delete_blob;
pub use get_blob::get_blob;
pub use get_blob_usage::get_blob_usage;
pub use get_group_metadata_blob::get_group_metadata_blob;
pub use put_group_metadata_blob::put_group_metadata_blob;
pub use upload_blob::upload_blob;

// Re-exports: Subscriptions
pub use get_subscription_ticket::get_subscription_ticket;

// Re-exports: Federation
pub use request_failover::request_failover;
