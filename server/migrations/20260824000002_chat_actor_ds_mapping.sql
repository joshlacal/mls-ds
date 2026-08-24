-- Actor to Delivery Service (DS) mapping table.
-- Maps an actor DID (e.g. did:plc:alice) to their home DS DID (e.g. did:web:chat.catbird.blue).
-- The target DS endpoint details remain in `ds_endpoints` keyed by the DS DID.

CREATE TABLE IF NOT EXISTS did_ds_mappings (
    actor_did TEXT PRIMARY KEY,
    ds_did TEXT NOT NULL,
    resolved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '1 hour'
);

CREATE INDEX IF NOT EXISTS idx_did_ds_mappings_expires ON did_ds_mappings(expires_at);

ALTER TABLE did_ds_mappings
    DROP CONSTRAINT IF EXISTS chk_did_ds_mappings_actor_did_canonical;
ALTER TABLE did_ds_mappings
    ADD CONSTRAINT chk_did_ds_mappings_actor_did_canonical
    CHECK (position('#' in actor_did) = 0);

ALTER TABLE did_ds_mappings
    DROP CONSTRAINT IF EXISTS chk_did_ds_mappings_ds_did_canonical;
ALTER TABLE did_ds_mappings
    ADD CONSTRAINT chk_did_ds_mappings_ds_did_canonical
    CHECK (position('#' in ds_did) = 0);

-- Purge unclassifiable legacy ds_endpoints cache entries (e.g. actor-keyed legacy rows).
DELETE FROM ds_endpoints;

ALTER TABLE ds_endpoints
    DROP CONSTRAINT IF EXISTS chk_ds_endpoints_did_canonical;
ALTER TABLE ds_endpoints
    ADD CONSTRAINT chk_ds_endpoints_did_canonical
    CHECK (position('#' in did) = 0);
