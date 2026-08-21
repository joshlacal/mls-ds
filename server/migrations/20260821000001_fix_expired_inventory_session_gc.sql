-- Fix GC and reclamation of inventory sessions without requiring superuser session_replication_role

CREATE OR REPLACE FUNCTION chat.enforce_immutable_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    mutable_columns TEXT[] := CASE
        WHEN TG_NARGS = 0 THEN ARRAY[]::TEXT[]
        ELSE TG_ARGV
    END;
BEGIN
    IF TG_OP = 'DELETE' THEN
        -- Allow cleanup/reclaim of ephemeral inventory sessions and their child rows
        IF TG_TABLE_NAME IN (
            'inventory_sessions',
            'device_inventory_sessions',
            'inventory_conversation_items',
            'inventory_welcome_items',
            'inventory_recovery_items',
            'subscription_tickets',
            'inventory_page_receipts',
            'event_cursor_receipts',
            'device_inventory_items'
        ) THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'immutable chat row cannot be deleted: %.%', TG_TABLE_SCHEMA, TG_TABLE_NAME
            USING ERRCODE = '23514';
    END IF;
    IF (to_jsonb(NEW) - mutable_columns)
       IS DISTINCT FROM (to_jsonb(OLD) - mutable_columns) THEN
        RAISE EXCEPTION 'immutable chat identity/provenance changed: %.%', TG_TABLE_SCHEMA, TG_TABLE_NAME
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION chat.gc_expired_inventory_sessions(batch_limit INTEGER)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    victims UUID[];
    removed BIGINT;
BEGIN
    IF batch_limit < 0 THEN batch_limit := 0; END IF;
    SELECT array_agg(inventory_session_id) INTO victims
      FROM (
        SELECT inventory_session_id
          FROM chat.inventory_sessions
         WHERE expires_at IS NOT NULL
           AND expires_at < now()
         ORDER BY expires_at
         FOR UPDATE SKIP LOCKED
         LIMIT batch_limit
      ) expired;
    IF victims IS NOT NULL THEN
        DELETE FROM chat.inventory_page_receipts WHERE inventory_session_id = ANY(victims);
        DELETE FROM chat.event_cursor_receipts WHERE inventory_session_id = ANY(victims);
        DELETE FROM chat.subscription_tickets WHERE inventory_session_id = ANY(victims);
        DELETE FROM chat.inventory_conversation_items WHERE inventory_session_id = ANY(victims);
        DELETE FROM chat.inventory_welcome_items WHERE inventory_session_id = ANY(victims);
        DELETE FROM chat.inventory_recovery_items WHERE inventory_session_id = ANY(victims);
        DELETE FROM chat.inventory_sessions WHERE inventory_session_id = ANY(victims);
        GET DIAGNOSTICS removed = ROW_COUNT;
    ELSE
        removed := 0;
    END IF;

    -- Also clean up any orphaned receipts
    DELETE FROM chat.inventory_page_receipts WHERE inventory_session_id NOT IN (SELECT inventory_session_id FROM chat.inventory_sessions);
    DELETE FROM chat.event_cursor_receipts WHERE inventory_session_id NOT IN (SELECT inventory_session_id FROM chat.inventory_sessions);

    RETURN removed;
END
$$;

CREATE OR REPLACE FUNCTION chat.gc_expired_device_inventory_sessions(batch_limit INTEGER)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    victims UUID[];
    removed BIGINT;
BEGIN
    IF batch_limit < 0 THEN batch_limit := 0; END IF;
    SELECT array_agg(device_inventory_session_id) INTO victims
      FROM (
        SELECT device_inventory_session_id
          FROM chat.device_inventory_sessions
         WHERE expires_at IS NOT NULL
           AND expires_at < now()
         ORDER BY expires_at
         FOR UPDATE SKIP LOCKED
         LIMIT batch_limit
      ) expired;
    IF victims IS NULL THEN RETURN 0; END IF;

    DELETE FROM chat.device_inventory_items WHERE device_inventory_session_id = ANY(victims);
    DELETE FROM chat.device_inventory_sessions WHERE device_inventory_session_id = ANY(victims);
    GET DIAGNOSTICS removed = ROW_COUNT;
    RETURN removed;
END
$$;
