-- =============================================================================
-- Migration: Key Package Deduplication and Welcome Validation
-- Date: 2025-11-13
-- Description: Add unique constraint on key packages, add reservation support
--              for welcome validation, and clean up historical duplicates
-- =============================================================================

-- Step 1: Add new columns for welcome validation reservation
-- These columns track when a key package is temporarily reserved during
-- welcome message validation to prevent race conditions

ALTER TABLE key_packages
    ADD COLUMN IF NOT EXISTS reserved_at TIMESTAMPTZ;

ALTER TABLE key_packages
    ADD COLUMN IF NOT EXISTS reserved_by_convo TEXT;

-- Step 2: Clean up historical duplicates
-- Keep the oldest key package for each (owner_did, key_package_hash) pair
-- Delete newer duplicates to prepare for unique constraint

WITH duplicates AS (
    SELECT
        id,
        ROW_NUMBER() OVER (
            PARTITION BY owner_did, key_package_hash
            ORDER BY created_at ASC
        ) as row_num
    FROM key_packages
)
DELETE FROM key_packages
WHERE id IN (
    SELECT id FROM duplicates WHERE row_num > 1
);

-- Step 3: Add unique constraint to prevent future duplicates
-- This ensures each user can only upload a unique key package once
-- (based on hash, regardless of cipher suite)

ALTER TABLE key_packages
    ADD CONSTRAINT key_packages_owner_hash_unique
    UNIQUE (owner_did, key_package_hash);

-- Step 4: Add index for reservation lookups
-- Helps efficiently find reserved packages that need expiration cleanup

CREATE INDEX IF NOT EXISTS idx_key_packages_reserved
    ON key_packages(reserved_at)
    WHERE reserved_at IS NOT NULL;

-- Step 5: Add index for hash-based lookups during welcome validation
-- Optimizes the common query pattern: find available package by hash

CREATE INDEX IF NOT EXISTS idx_key_packages_hash_available
    ON key_packages(owner_did, key_package_hash)
    WHERE consumed_at IS NULL;

-- Step 6: Add comment documentation for new columns

COMMENT ON COLUMN key_packages.reserved_at IS
    'Timestamp when key package was reserved during welcome validation. Expires after 5 minutes.';

COMMENT ON COLUMN key_packages.reserved_by_convo IS
    'Conversation ID that reserved this key package. Used to prevent race conditions during group joins.';

-- =============================================================================
-- Migration Notes:
--
-- Deduplication Strategy:
-- - Users can no longer upload the same key package (by hash) multiple times
-- - Duplicate upload attempts will be silently skipped (idempotent behavior)
-- - Historical duplicates are cleaned up, keeping oldest entry per hash
--
-- Reservation System:
-- - validateWelcome endpoint marks key packages as "reserved"
-- - Reservations expire after 5 minutes (matches welcome grace period)
-- - Prevents race condition where multiple welcome messages reference same package
-- - Consumed packages cannot be reserved (consumed_at takes precedence)
--
-- Performance:
-- - New unique constraint uses existing hash computation (no overhead)
-- - Reservation index helps background job clean expired reservations
-- - Hash lookup index optimized for "available" packages only
-- =============================================================================
