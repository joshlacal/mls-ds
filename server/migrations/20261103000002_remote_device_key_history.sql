-- Retain every signing key under its immutable historical proof identity.
-- enrollment_auth_generation is the first generation using a key, not the
-- current device generation: an unchanged key survives authentication rebinding.
-- The greatest activation <= a proof's generation is its only eligible key.
ALTER TABLE chat.device_keys
    DROP CONSTRAINT device_keys_pkey,
    ADD PRIMARY KEY (user_did, device_id, key_id),
    ADD CONSTRAINT device_keys_activation_generation_uq
        UNIQUE (user_did, device_id, enrollment_auth_generation);

-- Historical key-id / author-proof foreign keys and both immutable-key triggers
-- are deliberately unchanged. NULL-JKT service-authenticated remote devices may
-- have advanced multiple times while this DS was offline. Legacy DPoP bindings
-- still require exactly one generation per changed binding.
CREATE FUNCTION chat.enforce_device_auth_lifecycle_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status = 'revoked' AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'revoked device is terminal' USING ERRCODE = '23514';
    END IF;
    IF NEW.auth_generation < OLD.auth_generation
       OR ((OLD.dpop_jkt IS NOT NULL OR NEW.dpop_jkt IS NOT NULL)
           AND NEW.auth_generation > OLD.auth_generation + 1)
       OR (OLD.dpop_jkt IS NOT NULL AND NEW.dpop_jkt IS NOT NULL
           AND ((NEW.dpop_jkt IS DISTINCT FROM OLD.dpop_jkt)
                <> (NEW.auth_generation = OLD.auth_generation + 1)))
       OR NEW.updated_at < OLD.updated_at
       OR (OLD.status = 'active' AND NEW.status NOT IN ('active', 'revoked')) THEN
        RAISE EXCEPTION 'invalid device lifecycle transition' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER devices_lifecycle_monotonic ON chat.devices;
CREATE TRIGGER devices_lifecycle_monotonic
BEFORE UPDATE ON chat.devices
FOR EACH ROW EXECUTE FUNCTION chat.enforce_device_auth_lifecycle_transition();

-- Revocation still has exactly one current key and the same deferred receipt,
-- device and work-terminal proof. Older activation rows remain historical.
CREATE OR REPLACE FUNCTION chat.assert_device_revocation_mapping(target_revocation UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    revocation_row chat.device_revocations%ROWTYPE;
    target_key_count BIGINT;
BEGIN
    SELECT * INTO revocation_row
      FROM chat.device_revocations
     WHERE revocation_id = target_revocation;
    IF NOT FOUND THEN
        IF EXISTS (
            SELECT 1 FROM chat.devices WHERE revocation_id = target_revocation
            UNION ALL
            SELECT 1 FROM chat.device_keys WHERE revocation_id = target_revocation
            UNION ALL
            SELECT 1 FROM chat.key_packages WHERE terminal_revocation_id = target_revocation
            UNION ALL
            SELECT 1 FROM chat.key_package_reservations
             WHERE terminal_revocation_id = target_revocation
            UNION ALL
            SELECT 1 FROM chat.leaf_recovery_requests
             WHERE terminal_revocation_id = target_revocation
        ) THEN
            RAISE EXCEPTION 'device revocation provenance is missing'
                USING ERRCODE = '23514';
        END IF;
        RETURN;
    END IF;

    PERFORM 1 FROM chat.principals
     WHERE user_did = revocation_row.target_did
     FOR UPDATE;

    SELECT count(*) INTO target_key_count
      FROM chat.device_keys target_key
     WHERE target_key.user_did = revocation_row.target_did
       AND target_key.device_id = revocation_row.target_device_id
       AND target_key.enrollment_auth_generation <= revocation_row.target_auth_generation
       AND NOT EXISTS (
            SELECT 1 FROM chat.device_keys newer
             WHERE newer.user_did=target_key.user_did AND newer.device_id=target_key.device_id
               AND newer.enrollment_auth_generation>target_key.enrollment_auth_generation
               AND newer.enrollment_auth_generation<=revocation_row.target_auth_generation
       );

    IF target_key_count <> 1
       OR NOT EXISTS (
            SELECT 1
              FROM chat.devices target
             WHERE target.user_did = revocation_row.target_did
               AND target.device_id = revocation_row.target_device_id
               AND target.status = 'revoked'
               AND target.auth_generation = revocation_row.target_auth_generation
               AND target.revocation_id = revocation_row.revocation_id
               AND target.revoked_at = revocation_row.accepted_at
               AND target.updated_at = revocation_row.accepted_at
       )
       OR NOT EXISTS (
            SELECT 1
              FROM chat.device_keys target_key
             WHERE target_key.user_did = revocation_row.target_did
               AND target_key.device_id = revocation_row.target_device_id
               AND target_key.enrollment_auth_generation <= revocation_row.target_auth_generation
               AND NOT EXISTS (
                    SELECT 1 FROM chat.device_keys newer
                     WHERE newer.user_did=target_key.user_did AND newer.device_id=target_key.device_id
                       AND newer.enrollment_auth_generation>target_key.enrollment_auth_generation
                       AND newer.enrollment_auth_generation<=revocation_row.target_auth_generation
               )
               AND target_key.revocation_id = revocation_row.revocation_id
               AND target_key.revoked_at = revocation_row.accepted_at
       )
       OR NOT EXISTS (
            SELECT 1
              FROM chat.devices actor
              JOIN chat.device_keys actor_key
                ON actor_key.user_did = actor.user_did
               AND actor_key.device_id = actor.device_id
               AND actor_key.key_id = revocation_row.actor_key_id
             WHERE actor.user_did = revocation_row.actor_did
               AND actor.device_id = revocation_row.actor_device_id
               AND actor.auth_generation = revocation_row.actor_auth_generation
               AND actor_key.enrollment_auth_generation <= revocation_row.actor_auth_generation
               AND NOT EXISTS (
                    SELECT 1 FROM chat.device_keys newer
                     WHERE newer.user_did=actor_key.user_did AND newer.device_id=actor_key.device_id
                       AND newer.enrollment_auth_generation>actor_key.enrollment_auth_generation
                       AND newer.enrollment_auth_generation<=revocation_row.actor_auth_generation
               )
               AND actor.created_at <= revocation_row.accepted_at
               AND (actor.revoked_at IS NULL
                    OR actor.revoked_at >= revocation_row.accepted_at)
               AND actor_key.created_at <= revocation_row.accepted_at
               AND (actor_key.revoked_at IS NULL
                    OR actor_key.revoked_at >= revocation_row.accepted_at)
       )
       OR NOT EXISTS (
            SELECT 1
              FROM chat.idempotency_records receipt
             WHERE receipt.principal_did = revocation_row.actor_did
               AND receipt.endpoint_nsid = 'blue.catbird.chat.revokeDevice'
               AND receipt.operation_id = revocation_row.revocation_id
               AND receipt.request_digest = revocation_row.request_digest
               AND receipt.accepted_request_bytes = revocation_row.accepted_request_bytes
               AND receipt.signing_transcript_bytes = revocation_row.signing_transcript_bytes
               AND receipt.signature = revocation_row.signature
               AND receipt.completed_status BETWEEN 200 AND 299
               AND receipt.completed_at = revocation_row.accepted_at
       )
       OR EXISTS (
            SELECT 1 FROM chat.key_packages package
             WHERE package.owner_did = revocation_row.target_did
               AND package.owner_device_id = revocation_row.target_device_id
               AND package.status IN ('available','reserved')
       )
       OR EXISTS (
            SELECT 1 FROM chat.key_packages package
             WHERE package.terminal_revocation_id = revocation_row.revocation_id
               AND (package.owner_did, package.owner_device_id, package.status,
                    package.terminal_at)
                   IS DISTINCT FROM
                   (revocation_row.target_did, revocation_row.target_device_id,
                    'revoked'::TEXT, revocation_row.accepted_at)
       )
       OR EXISTS (
            SELECT 1 FROM chat.leaf_recovery_requests request
             WHERE request.requester_did = revocation_row.target_did
               AND request.requester_device_id = revocation_row.target_device_id
               AND request.status = 'open'
       )
       OR EXISTS (
            SELECT 1 FROM chat.key_package_reservations reservation
             WHERE reservation.recipient_did = revocation_row.target_did
               AND reservation.recipient_device_id = revocation_row.target_device_id
               AND reservation.status = 'active'
       ) THEN
        RAISE EXCEPTION 'device revocation terminal mapping mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;
