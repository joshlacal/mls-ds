-- Idempotency Cache Table
-- Created: 2025-11-02
-- Description: Cache for idempotent request responses with TTL support

-- Track idempotency results (for operations without persistent result)
CREATE TABLE IF NOT EXISTS idempotency_cache (
  key TEXT PRIMARY KEY,
  endpoint TEXT NOT NULL,
  response_body JSONB NOT NULL,
  status_code INTEGER NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_idempotency_expires
  ON idempotency_cache(expires_at);

CREATE INDEX IF NOT EXISTS idx_idempotency_endpoint
  ON idempotency_cache(endpoint);

-- Optional: Add idempotency_key columns to tables for permanent tracking
-- This allows storing the idempotency key alongside the actual data

ALTER TABLE messages
  ADD COLUMN IF NOT EXISTS idempotency_key TEXT;

CREATE INDEX IF NOT EXISTS idx_messages_idempotency
  ON messages(idempotency_key) WHERE idempotency_key IS NOT NULL;

ALTER TABLE conversations
  ADD COLUMN IF NOT EXISTS idempotency_key TEXT;

CREATE INDEX IF NOT EXISTS idx_conversations_idempotency
  ON conversations(idempotency_key) WHERE idempotency_key IS NOT NULL;

-- Note: We don't add UNIQUE constraints yet to avoid breaking existing data
-- In Phase 2, consider adding UNIQUE constraints after migrating data
