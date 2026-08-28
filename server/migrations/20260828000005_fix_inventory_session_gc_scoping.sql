-- Reclaim expired inventory sessions without disabling PostgreSQL triggers.

CREATE OR REPLACE FUNCTION chat.enforce_immutable_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    mutable_columns TEXT[] := CASE
        WHEN TG_NARGS = 0 THEN ARRAY[]::TEXT[]
        ELSE TG_ARGV
    END;
    delete_scope TEXT;
BEGIN
    IF TG_OP = 'DELETE' THEN
        delete_scope := current_setting('chat.inventory_gc_delete_table', true);
        IF TG_TABLE_SCHEMA = 'chat'
           AND TG_TABLE_NAME IN (
               'inventory_sessions',
               'device_inventory_sessions',
               'inventory_conversation_items',
               'inventory_welcome_items',
               'inventory_recovery_items',
               'subscription_tickets',
               'inventory_page_receipts',
               'event_cursor_receipts',
               'device_inventory_items'
           )
           AND delete_scope = format(
               '%s:%s.%s',
               txid_current(),
               TG_TABLE_SCHEMA,
               TG_TABLE_NAME
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
    removed BIGINT := 0;
    previous_delete_scope TEXT;
    delete_scope_prefix TEXT;
    target_user_did TEXT;
    target_device_id UUID;
    target_device_text TEXT;
BEGIN
    IF batch_limit < 0 THEN batch_limit := 0; END IF;
    previous_delete_scope := current_setting('chat.inventory_gc_delete_table', true);
    delete_scope_prefix := txid_current()::TEXT || ':chat.';
    target_user_did := NULLIF(current_setting('chat.inventory_gc_target_user_did', true), '');
    target_device_text := NULLIF(current_setting('chat.inventory_gc_target_device_id', true), '');
    IF (target_user_did IS NULL) <> (target_device_text IS NULL) THEN
        RAISE EXCEPTION 'inventory GC target must include both user DID and device ID'
            USING ERRCODE = '22023';
    END IF;
    IF target_device_text IS NOT NULL THEN
        target_device_id := target_device_text::UUID;
    END IF;
    PERFORM set_config('chat.inventory_gc_target_user_did', '', true);
    PERFORM set_config('chat.inventory_gc_target_device_id', '', true);

    SELECT array_agg(inventory_session_id) INTO victims
      FROM (
        SELECT inventory_session_id
          FROM chat.inventory_sessions
         WHERE expires_at IS NOT NULL
           AND expires_at < now()
           AND (
               target_user_did IS NULL
               OR (user_did = target_user_did AND device_id = target_device_id)
           )
         ORDER BY expires_at
         FOR UPDATE SKIP LOCKED
         LIMIT batch_limit
      ) expired;
    IF victims IS NOT NULL THEN
        PERFORM set_config('chat.inventory_gc_delete_table', delete_scope_prefix || 'inventory_page_receipts', true);
        DELETE FROM chat.inventory_page_receipts WHERE inventory_session_id = ANY(victims);
        PERFORM set_config('chat.inventory_gc_delete_table', delete_scope_prefix || 'event_cursor_receipts', true);
        DELETE FROM chat.event_cursor_receipts WHERE inventory_session_id = ANY(victims);
        PERFORM set_config('chat.inventory_gc_delete_table', delete_scope_prefix || 'subscription_tickets', true);
        DELETE FROM chat.subscription_tickets WHERE inventory_session_id = ANY(victims);
        PERFORM set_config('chat.inventory_gc_delete_table', delete_scope_prefix || 'inventory_conversation_items', true);
        DELETE FROM chat.inventory_conversation_items WHERE inventory_session_id = ANY(victims);
        PERFORM set_config('chat.inventory_gc_delete_table', delete_scope_prefix || 'inventory_welcome_items', true);
        DELETE FROM chat.inventory_welcome_items WHERE inventory_session_id = ANY(victims);
        PERFORM set_config('chat.inventory_gc_delete_table', delete_scope_prefix || 'inventory_recovery_items', true);
        DELETE FROM chat.inventory_recovery_items WHERE inventory_session_id = ANY(victims);
        PERFORM set_config('chat.inventory_gc_delete_table', delete_scope_prefix || 'inventory_sessions', true);
        DELETE FROM chat.inventory_sessions WHERE inventory_session_id = ANY(victims);
        GET DIAGNOSTICS removed = ROW_COUNT;
    END IF;

    -- Older deployments could leave orphan receipts. Only untargeted
    -- background GC may drain them, and each pass is bounded.
    IF target_user_did IS NULL THEN
        PERFORM set_config('chat.inventory_gc_delete_table', delete_scope_prefix || 'inventory_page_receipts', true);
        DELETE FROM chat.inventory_page_receipts
         WHERE ctid IN (
            SELECT receipt.ctid
              FROM chat.inventory_page_receipts AS receipt
             WHERE NOT EXISTS (
                SELECT 1
                  FROM chat.inventory_sessions AS session
                 WHERE session.inventory_session_id = receipt.inventory_session_id
             )
             ORDER BY receipt.ctid
             FOR UPDATE OF receipt SKIP LOCKED
             LIMIT batch_limit
         );
        PERFORM set_config('chat.inventory_gc_delete_table', delete_scope_prefix || 'event_cursor_receipts', true);
        DELETE FROM chat.event_cursor_receipts
         WHERE ctid IN (
            SELECT receipt.ctid
              FROM chat.event_cursor_receipts AS receipt
             WHERE NOT EXISTS (
                SELECT 1
                  FROM chat.inventory_sessions AS session
                 WHERE session.inventory_session_id = receipt.inventory_session_id
             )
             ORDER BY receipt.ctid
             FOR UPDATE OF receipt SKIP LOCKED
             LIMIT batch_limit
         );
    END IF;

    PERFORM set_config(
        'chat.inventory_gc_delete_table',
        COALESCE(previous_delete_scope, ''),
        true
    );
    RETURN removed;
EXCEPTION WHEN OTHERS THEN
    PERFORM set_config(
        'chat.inventory_gc_delete_table',
        COALESCE(previous_delete_scope, ''),
        true
    );
    RAISE;
END
$$;

CREATE OR REPLACE FUNCTION chat.gc_expired_device_inventory_sessions(batch_limit INTEGER)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    victims UUID[];
    removed BIGINT := 0;
    previous_delete_scope TEXT;
    delete_scope_prefix TEXT;
    target_user_did TEXT;
    target_device_id UUID;
    target_device_text TEXT;
BEGIN
    IF batch_limit < 0 THEN batch_limit := 0; END IF;
    previous_delete_scope := current_setting('chat.inventory_gc_delete_table', true);
    delete_scope_prefix := txid_current()::TEXT || ':chat.';
    target_user_did := NULLIF(current_setting('chat.inventory_gc_target_user_did', true), '');
    target_device_text := NULLIF(current_setting('chat.inventory_gc_target_device_id', true), '');
    IF (target_user_did IS NULL) <> (target_device_text IS NULL) THEN
        RAISE EXCEPTION 'device inventory GC target must include both user DID and device ID'
            USING ERRCODE = '22023';
    END IF;
    IF target_device_text IS NOT NULL THEN
        target_device_id := target_device_text::UUID;
    END IF;
    PERFORM set_config('chat.inventory_gc_target_user_did', '', true);
    PERFORM set_config('chat.inventory_gc_target_device_id', '', true);

    SELECT array_agg(device_inventory_session_id) INTO victims
      FROM (
        SELECT device_inventory_session_id
          FROM chat.device_inventory_sessions
         WHERE (
               target_user_did IS NOT NULL
               AND user_did = target_user_did
               AND device_id = target_device_id
           )
            OR (
               target_user_did IS NULL
               AND expires_at IS NOT NULL
               AND expires_at < now()
           )
         ORDER BY expires_at
         FOR UPDATE SKIP LOCKED
         LIMIT batch_limit
      ) expired;
    IF victims IS NOT NULL THEN
        PERFORM set_config('chat.inventory_gc_delete_table', delete_scope_prefix || 'device_inventory_items', true);
        DELETE FROM chat.device_inventory_items WHERE device_inventory_session_id = ANY(victims);
        PERFORM set_config('chat.inventory_gc_delete_table', delete_scope_prefix || 'device_inventory_sessions', true);
        DELETE FROM chat.device_inventory_sessions WHERE device_inventory_session_id = ANY(victims);
        GET DIAGNOSTICS removed = ROW_COUNT;
    END IF;

    PERFORM set_config(
        'chat.inventory_gc_delete_table',
        COALESCE(previous_delete_scope, ''),
        true
    );
    RETURN removed;
EXCEPTION WHEN OTHERS THEN
    PERFORM set_config(
        'chat.inventory_gc_delete_table',
        COALESCE(previous_delete_scope, ''),
        true
    );
    RAISE;
END
$$;

CREATE OR REPLACE FUNCTION chat.delete_inventory_session_exact(
    target_inventory_session_id UUID,
    target_user_did TEXT,
    target_device_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    removed BIGINT := 0;
    previous_delete_scope TEXT;
    delete_scope_prefix TEXT;
BEGIN
    previous_delete_scope := current_setting('chat.inventory_gc_delete_table', true);
    delete_scope_prefix := txid_current()::TEXT || ':chat.';
    IF target_user_did IS NULL OR target_device_id IS NULL THEN
        RAISE EXCEPTION 'exact inventory delete requires user DID and device ID'
            USING ERRCODE = '22023';
    END IF;

    PERFORM 1
      FROM chat.inventory_sessions AS session
     WHERE session.inventory_session_id = target_inventory_session_id
       AND session.user_did = target_user_did
       AND session.device_id = target_device_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    PERFORM set_config('chat.inventory_gc_delete_table', delete_scope_prefix || 'inventory_page_receipts', true);
    DELETE FROM chat.inventory_page_receipts WHERE inventory_session_id = target_inventory_session_id;
    PERFORM set_config('chat.inventory_gc_delete_table', delete_scope_prefix || 'event_cursor_receipts', true);
    DELETE FROM chat.event_cursor_receipts WHERE inventory_session_id = target_inventory_session_id;
    PERFORM set_config('chat.inventory_gc_delete_table', delete_scope_prefix || 'subscription_tickets', true);
    DELETE FROM chat.subscription_tickets WHERE inventory_session_id = target_inventory_session_id;
    PERFORM set_config('chat.inventory_gc_delete_table', delete_scope_prefix || 'inventory_conversation_items', true);
    DELETE FROM chat.inventory_conversation_items WHERE inventory_session_id = target_inventory_session_id;
    PERFORM set_config('chat.inventory_gc_delete_table', delete_scope_prefix || 'inventory_welcome_items', true);
    DELETE FROM chat.inventory_welcome_items WHERE inventory_session_id = target_inventory_session_id;
    PERFORM set_config('chat.inventory_gc_delete_table', delete_scope_prefix || 'inventory_recovery_items', true);
    DELETE FROM chat.inventory_recovery_items WHERE inventory_session_id = target_inventory_session_id;
    PERFORM set_config('chat.inventory_gc_delete_table', delete_scope_prefix || 'inventory_sessions', true);
    DELETE FROM chat.inventory_sessions WHERE inventory_session_id = target_inventory_session_id;
    GET DIAGNOSTICS removed = ROW_COUNT;

    PERFORM set_config(
        'chat.inventory_gc_delete_table',
        COALESCE(previous_delete_scope, ''),
        true
    );
    RETURN removed = 1;
EXCEPTION WHEN OTHERS THEN
    PERFORM set_config(
        'chat.inventory_gc_delete_table',
        COALESCE(previous_delete_scope, ''),
        true
    );
    RAISE;
END
$$;
