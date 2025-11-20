-- Create table for tracking key package notification history
-- This prevents notification spam by recording when users were last notified

CREATE TABLE IF NOT EXISTS key_package_notifications (
    id BIGSERIAL PRIMARY KEY,
    user_did TEXT NOT NULL,
    notification_type TEXT NOT NULL,
    notified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Ensure one row per user per notification type
    UNIQUE(user_did, notification_type)
);

-- Index for efficient lookups by user and notification type
CREATE INDEX IF NOT EXISTS idx_kp_notifications_user_type
    ON key_package_notifications(user_did, notification_type);

-- Index for cleanup queries (finding old notifications)
CREATE INDEX IF NOT EXISTS idx_kp_notifications_notified_at
    ON key_package_notifications(notified_at);

-- Comments for documentation
COMMENT ON TABLE key_package_notifications IS
    'Tracks when users were last notified about key package events to prevent spam';

COMMENT ON COLUMN key_package_notifications.user_did IS
    'DID of the user who was notified';

COMMENT ON COLUMN key_package_notifications.notification_type IS
    'Type of notification (e.g., low_inventory, expired_packages)';

COMMENT ON COLUMN key_package_notifications.notified_at IS
    'Timestamp when the notification was last sent (updated on each send)';
