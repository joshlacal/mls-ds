-- Idempotency Keys and Cache
-- Created: 2025-11-02
-- Description: Add idempotency support for messages and conversations to prevent
-- duplicate operations, plus a general idempotency cache for API operations

-- Enable pgcrypto extension if not already enabled
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =============================================================================
-- Add Idempotency Keys to Existing Tables
-- =============================================================================

-- Add idempotency_key to messages table
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'messages'
        AND column_name = 'idempotency_key'
    ) THEN
        ALTER TABLE messages
        ADD COLUMN idempotency_key TEXT;
    END IF;
END $$;

-- Create unique constraint on messages.idempotency_key
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'messages_idempotency_key_unique'
    ) THEN
        ALTER TABLE messages
        ADD CONSTRAINT messages_idempotency_key_unique
        UNIQUE (idempotency_key);
    END IF;
END $$;

-- Add idempotency_key to conversations table
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'conversations'
        AND column_name = 'idempotency_key'
    ) THEN
        ALTER TABLE conversations
        ADD COLUMN idempotency_key TEXT;
    END IF;
END $$;

-- Create unique constraint on conversations.idempotency_key
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'conversations_idempotency_key_unique'
    ) THEN
        ALTER TABLE conversations
        ADD CONSTRAINT conversations_idempotency_key_unique
        UNIQUE (idempotency_key);
    END IF;
END $$;

-- =============================================================================
-- Idempotency Cache Table
-- =============================================================================

-- Create idempotency_cache table for general API operation idempotency
-- This table stores cached responses for idempotent requests
CREATE TABLE IF NOT EXISTS idempotency_cache (
    key TEXT PRIMARY KEY,
    endpoint TEXT NOT NULL,
    response_body JSONB NOT NULL,
    status_code INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

-- Index on expires_at for efficient cleanup of expired entries
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE indexname = 'idx_idempotency_cache_expires'
    ) THEN
        CREATE INDEX idx_idempotency_cache_expires
        ON idempotency_cache(expires_at);
    END IF;
END $$;

-- Index on endpoint for debugging and monitoring
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE indexname = 'idx_idempotency_cache_endpoint'
    ) THEN
        CREATE INDEX idx_idempotency_cache_endpoint
        ON idempotency_cache(endpoint, created_at DESC);
    END IF;
END $$;

-- =============================================================================
-- Cleanup Function
-- =============================================================================

-- Function to clean up expired idempotency cache entries
-- Should be called periodically (e.g., via cron or scheduled task)
CREATE OR REPLACE FUNCTION cleanup_expired_idempotency_cache()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM idempotency_cache
    WHERE expires_at < NOW();

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;
