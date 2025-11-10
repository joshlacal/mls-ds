-- Migration: Add indices for key package consumption tracking
-- Date: 2025-11-10
-- Description: Optimize queries for consumption rate calculations and batch lookups

-- Index for consumption rate queries (7-day consumption tracking)
-- Used by get_consumption_rate() to calculate packages per day
CREATE INDEX IF NOT EXISTS idx_key_packages_consumed_at
ON key_packages(did, consumed_at DESC)
WHERE consumed = true;

-- Index for quick hash lookups during batch operations
-- Used by mark_key_package_consumed() to find packages by hash
CREATE INDEX IF NOT EXISTS idx_key_packages_hash_lookup
ON key_packages(did, key_package_hash)
WHERE consumed = false;

-- Index for efficient counting of consumed packages in time windows
-- Used by count_consumed_key_packages() for 24h and 7d stats
CREATE INDEX IF NOT EXISTS idx_key_packages_consumed_time_range
ON key_packages(did, consumed_at)
WHERE consumed = true AND consumed_at IS NOT NULL;

-- Comment on indices
COMMENT ON INDEX idx_key_packages_consumed_at IS 'Optimizes consumption rate calculations (packages per day)';
COMMENT ON INDEX idx_key_packages_hash_lookup IS 'Speeds up key package consumption marking by hash during group operations';
COMMENT ON INDEX idx_key_packages_consumed_time_range IS 'Optimizes time-range consumption queries (24h, 7d stats)';
