-- Delivery acknowledgments from remote DSes confirming receipt of forwarded messages.
CREATE TABLE IF NOT EXISTS delivery_acks (
    id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL,
    convo_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    target_ds_did TEXT NOT NULL,
    acked_at BIGINT NOT NULL,
    signature BYTEA NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_delivery_acks_message 
    ON delivery_acks (message_id);
CREATE INDEX IF NOT EXISTS idx_delivery_acks_convo 
    ON delivery_acks (convo_id, message_id);
