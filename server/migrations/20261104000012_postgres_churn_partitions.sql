-- PostgreSQL 16 churn controls for terminal transport history and hot mutable rows.
-- Active queue rows remain in DEFAULT partitions (terminal_at IS NULL).  The first
-- terminal transition stamps terminal_at and routes the immutable history row to
-- a monthly partition.  Maintenance creates two months ahead and drops only a
-- whole month whose upper bound is at least seven days old.

LOCK TABLE public.outbound_queue, public.federation_outbox IN ACCESS EXCLUSIVE MODE;

ALTER TABLE public.outbound_queue RENAME TO outbound_queue_unpartitioned;

CREATE TABLE public.outbound_queue (
    id TEXT NOT NULL,
    target_ds_did TEXT NOT NULL,
    target_endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    payload BYTEA NOT NULL,
    convo_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    next_retry_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retry_count INTEGER NOT NULL DEFAULT 0,
    max_retries INTEGER NOT NULL DEFAULT 5,
    last_error TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    claim_token UUID,
    claim_expires_at TIMESTAMPTZ,
    payload_sha256 BYTEA,
    envelope_version INTEGER NOT NULL DEFAULT 1,
    terminal_at TIMESTAMPTZ,
    CONSTRAINT outbound_queue_status_check
        CHECK (status IN ('pending', 'in_flight', 'delivered', 'failed', 'dead')),
    CONSTRAINT outbound_queue_terminal_shape_check
        CHECK (terminal_at IS NULL OR status IN ('delivered', 'failed', 'dead')),
    CONSTRAINT outbound_queue_id_terminal_uq
        UNIQUE NULLS NOT DISTINCT (id, terminal_at)
) PARTITION BY RANGE (terminal_at);

CREATE TABLE public.outbound_queue_default
    PARTITION OF public.outbound_queue DEFAULT;

INSERT INTO public.outbound_queue (
    id, target_ds_did, target_endpoint, method, payload, convo_id, created_at,
    next_retry_at, retry_count, max_retries, last_error, status, claim_token,
    claim_expires_at, payload_sha256, envelope_version, terminal_at
)
SELECT id, target_ds_did, target_endpoint, method, payload, convo_id, created_at,
       next_retry_at, retry_count, max_retries, last_error, status, claim_token,
       claim_expires_at, payload_sha256, envelope_version,
       CASE WHEN status IN ('delivered', 'failed', 'dead') THEN created_at END
  FROM public.outbound_queue_unpartitioned;

DO $$
BEGIN
    IF (SELECT count(*) FROM public.outbound_queue)
       <> (SELECT count(*) FROM public.outbound_queue_unpartitioned) THEN
        RAISE EXCEPTION 'outbound_queue partition migration lost rows';
    END IF;
END
$$;

DROP TABLE public.outbound_queue_unpartitioned;

CREATE INDEX idx_outbound_queue_due_v2
    ON public.outbound_queue (next_retry_at) WHERE status = 'pending';
CREATE INDEX idx_outbound_queue_lease
    ON public.outbound_queue (claim_expires_at) WHERE status = 'in_flight';
CREATE INDEX idx_outbound_queue_convo
    ON public.outbound_queue (convo_id);

ALTER TABLE public.federation_outbox RENAME TO federation_outbox_unpartitioned;

CREATE TABLE public.federation_outbox (
    id TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    delivery_event_id TEXT,
    target_service_did TEXT NOT NULL,
    payload BYTEA NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT NOT NULL DEFAULT 'pending',
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    method TEXT NOT NULL DEFAULT 'blue.catbird.mlsDS.deliverMessage',
    payload_sha256 BYTEA,
    envelope_version INTEGER NOT NULL DEFAULT 1,
    claim_token UUID,
    claim_expires_at TIMESTAMPTZ,
    terminal_at TIMESTAMPTZ,
    CONSTRAINT federation_outbox_status_check
        CHECK (status IN ('pending', 'in_flight', 'done', 'failed', 'dead')),
    CONSTRAINT federation_outbox_terminal_shape_check
        CHECK (terminal_at IS NULL OR status IN ('done', 'failed', 'dead')),
    CONSTRAINT federation_outbox_id_terminal_uq
        UNIQUE NULLS NOT DISTINCT (id, terminal_at)
) PARTITION BY RANGE (terminal_at);

CREATE TABLE public.federation_outbox_default
    PARTITION OF public.federation_outbox DEFAULT;

INSERT INTO public.federation_outbox (
    id, conversation_id, delivery_event_id, target_service_did, payload, attempts,
    next_attempt_at, status, last_error, created_at, updated_at, method,
    payload_sha256, envelope_version, claim_token, claim_expires_at, terminal_at
)
SELECT id, conversation_id, delivery_event_id, target_service_did, payload, attempts,
       next_attempt_at, status, last_error, created_at, updated_at, method,
       payload_sha256, envelope_version, claim_token, claim_expires_at,
       CASE WHEN status IN ('done', 'failed', 'dead') THEN COALESCE(updated_at, created_at) END
  FROM public.federation_outbox_unpartitioned;

DO $$
BEGIN
    IF (SELECT count(*) FROM public.federation_outbox)
       <> (SELECT count(*) FROM public.federation_outbox_unpartitioned) THEN
        RAISE EXCEPTION 'federation_outbox partition migration lost rows';
    END IF;
END
$$;

DROP TABLE public.federation_outbox_unpartitioned;

CREATE INDEX idx_federation_outbox_due_v2
    ON public.federation_outbox (next_attempt_at) WHERE status = 'pending';
CREATE INDEX idx_federation_outbox_lease
    ON public.federation_outbox (claim_expires_at) WHERE status = 'in_flight';
CREATE INDEX idx_federation_outbox_conversation
    ON public.federation_outbox (conversation_id);

CREATE FUNCTION public.route_outbound_queue_terminal_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status IN ('delivered', 'failed', 'dead') THEN
        IF OLD.terminal_at IS NOT NULL THEN
            NEW.terminal_at := OLD.terminal_at;
        ELSE
            NEW.terminal_at := COALESCE(NEW.terminal_at, clock_timestamp());
        END IF;
    ELSE
        NEW.terminal_at := NULL;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER a_route_outbound_queue_terminal_at
BEFORE UPDATE OF status, terminal_at ON public.outbound_queue
FOR EACH ROW EXECUTE FUNCTION public.route_outbound_queue_terminal_at();

CREATE FUNCTION public.route_federation_outbox_terminal_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status IN ('done', 'failed', 'dead') THEN
        IF OLD.terminal_at IS NOT NULL THEN
            NEW.terminal_at := OLD.terminal_at;
        ELSE
            NEW.terminal_at := COALESCE(NEW.terminal_at, clock_timestamp());
        END IF;
    ELSE
        NEW.terminal_at := NULL;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER a_route_federation_outbox_terminal_at
BEFORE UPDATE OF status, terminal_at ON public.federation_outbox
FOR EACH ROW EXECUTE FUNCTION public.route_federation_outbox_terminal_at();

-- Partition routing is chosen before a BEFORE INSERT trigger runs, so a
-- terminal row inserted without terminal_at must be stamped by an AFTER trigger.
-- Its self-update then uses the ordinary BEFORE UPDATE router above.
CREATE FUNCTION public.finalize_inserted_transport_terminal_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    parent_table regclass := TG_ARGV[0]::regclass;
BEGIN
    IF NEW.status NOT IN ('pending', 'in_flight') AND NEW.terminal_at IS NULL THEN
        EXECUTE format(
            'UPDATE %s SET terminal_at = clock_timestamp() WHERE id = $1 AND terminal_at IS NULL',
            parent_table
        ) USING NEW.id;
    END IF;
    RETURN NULL;
END
$$;

CREATE TRIGGER b_finalize_outbound_queue_terminal_at
AFTER INSERT ON public.outbound_queue
FOR EACH ROW EXECUTE FUNCTION public.finalize_inserted_transport_terminal_at(
    'public.outbound_queue'
);

CREATE TRIGGER b_finalize_federation_outbox_terminal_at
AFTER INSERT ON public.federation_outbox
FOR EACH ROW EXECUTE FUNCTION public.finalize_inserted_transport_terminal_at(
    'public.federation_outbox'
);

-- PostgreSQL cannot express a global unique key whose partition key is nullable.
-- The per-partition UNIQUE NULLS NOT DISTINCT constraint handles concurrent active
-- inserts; this trigger preserves the old global id invariant across months.
CREATE FUNCTION public.guard_transport_history_id()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    parent_table regclass := TG_ARGV[0]::regclass;
    duplicate_exists BOOLEAN;
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.id = OLD.id THEN
        RETURN NEW;
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(parent_table::text || ':' || NEW.id, 0));
    EXECUTE format(
        'SELECT EXISTS (SELECT 1 FROM %s WHERE id = $1 AND terminal_at IS DISTINCT FROM $2)',
        parent_table
    )
       INTO duplicate_exists
       USING NEW.id, NEW.terminal_at;
    IF duplicate_exists THEN
        RAISE unique_violation USING
            MESSAGE = format('duplicate transport history id %L', NEW.id),
            TABLE = TG_TABLE_NAME,
            SCHEMA = TG_TABLE_SCHEMA;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER z_guard_outbound_queue_id
BEFORE INSERT OR UPDATE OF id ON public.outbound_queue
FOR EACH ROW EXECUTE FUNCTION public.guard_transport_history_id('public.outbound_queue');

CREATE TRIGGER z_guard_federation_outbox_id
BEFORE INSERT OR UPDATE OF id ON public.federation_outbox
FOR EACH ROW EXECUTE FUNCTION public.guard_transport_history_id('public.federation_outbox');

CREATE FUNCTION public.maintain_transport_partitions(
    parent_table regclass,
    retain_for INTERVAL DEFAULT INTERVAL '7 days',
    observed_at TIMESTAMPTZ DEFAULT clock_timestamp(),
    drop_expired BOOLEAN DEFAULT TRUE,
    months_ahead INTEGER DEFAULT 2
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    parent_schema NAME;
    parent_name NAME;
    default_name NAME;
    partition_name NAME;
    stage_name NAME;
    months_name NAME;
    month_start TIMESTAMPTZ;
    month_end TIMESTAMPTZ;
    partition_oid OID;
    dropped_partitions BIGINT := 0;
    offset_month INTEGER;
BEGIN
    IF parent_table NOT IN (
        'public.outbound_queue'::regclass,
        'public.federation_outbox'::regclass
    ) THEN
        RAISE EXCEPTION 'unsupported transport partition parent: %', parent_table;
    END IF;
    IF retain_for <= INTERVAL '0' THEN
        RAISE EXCEPTION 'transport partition retention must be positive';
    END IF;
    IF months_ahead NOT BETWEEN 0 AND 24 THEN
        RAISE EXCEPTION 'months_ahead must be between zero and 24';
    END IF;

    SELECT namespace.nspname, parent.relname
      INTO parent_schema, parent_name
      FROM pg_class parent
      JOIN pg_namespace namespace ON namespace.oid = parent.relnamespace
     WHERE parent.oid = parent_table
       AND parent.relkind = 'p';
    IF parent_name IS NULL THEN
        RAISE EXCEPTION '% is not a partitioned table', parent_table;
    END IF;

    default_name := parent_name || '_default';
    stage_name := parent_name || '_partition_stage';
    months_name := parent_name || '_partition_months';

    PERFORM pg_advisory_xact_lock(hashtextextended(parent_table::text || ':partition-maintenance', 0));
    EXECUTE format('LOCK TABLE %I.%I IN ACCESS EXCLUSIVE MODE', parent_schema, default_name);

    EXECUTE format('DROP TABLE IF EXISTS pg_temp.%I', stage_name);
    EXECUTE format('DROP TABLE IF EXISTS pg_temp.%I', months_name);
    EXECUTE format(
        'CREATE TEMP TABLE %I (LIKE %I.%I INCLUDING DEFAULTS) ON COMMIT DROP',
        stage_name, parent_schema, parent_name
    );
    EXECUTE format(
        'CREATE TEMP TABLE %I (month_start TIMESTAMPTZ PRIMARY KEY) ON COMMIT DROP',
        months_name
    );

    FOR offset_month IN 0..months_ahead LOOP
        month_start := date_trunc('month', observed_at, 'UTC')
            + make_interval(months => offset_month);
        EXECUTE format(
            'INSERT INTO pg_temp.%I VALUES ($1) ON CONFLICT DO NOTHING',
            months_name
        ) USING month_start;
    END LOOP;

    EXECUTE format(
        'INSERT INTO pg_temp.%I '
        'SELECT DISTINCT date_trunc(''month'', terminal_at, ''UTC'') '
        'FROM %I.%I WHERE terminal_at IS NOT NULL ON CONFLICT DO NOTHING',
        months_name, parent_schema, default_name
    );

    FOR month_start IN EXECUTE format(
        'SELECT month_start FROM pg_temp.%I ORDER BY month_start', months_name
    ) LOOP
        month_end := month_start + INTERVAL '1 month';
        partition_name := parent_name || '_' || to_char(month_start AT TIME ZONE 'UTC', 'YYYYMM');

        SELECT child.oid
          INTO partition_oid
          FROM pg_inherits inheritance
          JOIN pg_class child ON child.oid = inheritance.inhrelid
         WHERE inheritance.inhparent = parent_table
           AND child.relname = partition_name;

        IF partition_oid IS NULL THEN
            IF to_regclass(format('%I.%I', parent_schema, partition_name)) IS NOT NULL THEN
                RAISE EXCEPTION 'relation %.% exists but is not attached to %',
                    parent_schema, partition_name, parent_table;
            END IF;

            EXECUTE format('TRUNCATE pg_temp.%I', stage_name);
            EXECUTE format(
                'INSERT INTO pg_temp.%I SELECT * FROM %I.%I '
                'WHERE terminal_at >= $1 AND terminal_at < $2',
                stage_name, parent_schema, default_name
            ) USING month_start, month_end;
            EXECUTE format(
                'DELETE FROM %I.%I WHERE terminal_at >= $1 AND terminal_at < $2',
                parent_schema, default_name
            ) USING month_start, month_end;
            EXECUTE format(
                'CREATE TABLE %I.%I PARTITION OF %I.%I '
                'FOR VALUES FROM (%L) TO (%L)',
                parent_schema, partition_name, parent_schema, parent_name,
                month_start, month_end
            );
            EXECUTE format(
                'INSERT INTO %I.%I SELECT * FROM pg_temp.%I',
                parent_schema, parent_name, stage_name
            );
        END IF;
    END LOOP;

    IF drop_expired THEN
        FOR partition_name IN
            SELECT child.relname
              FROM pg_inherits inheritance
              JOIN pg_class child ON child.oid = inheritance.inhrelid
             WHERE inheritance.inhparent = parent_table
               AND child.relname ~ ('^' || parent_name || '_[0-9]{6}$')
             ORDER BY child.relname
        LOOP
            month_start := make_timestamptz(
                substring(partition_name FROM '([0-9]{4})[0-9]{2}$')::INTEGER,
                substring(partition_name FROM '[0-9]{4}([0-9]{2})$')::INTEGER,
                1, 0, 0, 0, 'UTC'
            );
            IF month_start + INTERVAL '1 month' <= observed_at - retain_for THEN
                EXECUTE format('DROP TABLE %I.%I', parent_schema, partition_name);
                dropped_partitions := dropped_partitions + 1;
            END IF;
        END LOOP;
    END IF;

    EXECUTE format('DROP TABLE pg_temp.%I', stage_name);
    EXECUTE format('DROP TABLE pg_temp.%I', months_name);
    RETURN dropped_partitions;
END
$$;

-- Route existing terminal rows and provision current + two future months without
-- deleting anything during the upgrade transaction.
SELECT public.maintain_transport_partitions(
    'public.outbound_queue'::regclass, INTERVAL '7 days', clock_timestamp(), FALSE, 2
);
SELECT public.maintain_transport_partitions(
    'public.federation_outbox'::regclass, INTERVAL '7 days', clock_timestamp(), FALSE, 2
);

-- Churn-heavy package reservation rows need threshold-based vacuum/analyze far
-- below PostgreSQL's table defaults.  Conversations trade space for HOT updates.
ALTER TABLE chat.key_packages SET (
    autovacuum_vacuum_scale_factor = 0.01,
    autovacuum_analyze_scale_factor = 0.01
);
ALTER TABLE chat.key_package_reservations SET (
    autovacuum_vacuum_scale_factor = 0.01,
    autovacuum_analyze_scale_factor = 0.01
);
ALTER TABLE chat.direct_request_lifecycle_reserves SET (
    autovacuum_vacuum_scale_factor = 0.01,
    autovacuum_analyze_scale_factor = 0.01
);
ALTER TABLE chat.direct_request_decision_slots SET (
    autovacuum_vacuum_scale_factor = 0.01,
    autovacuum_analyze_scale_factor = 0.01
);
ALTER TABLE chat.direct_request_welcome_slots SET (
    autovacuum_vacuum_scale_factor = 0.01,
    autovacuum_analyze_scale_factor = 0.01
);
ALTER TABLE chat.direct_request_remote_leases SET (
    autovacuum_vacuum_scale_factor = 0.01,
    autovacuum_analyze_scale_factor = 0.01
);
ALTER TABLE chat.direct_request_reservation_intents SET (
    autovacuum_vacuum_scale_factor = 0.01,
    autovacuum_analyze_scale_factor = 0.01
);
ALTER TABLE chat.direct_request_reserved_remote_packages SET (
    autovacuum_vacuum_scale_factor = 0.01,
    autovacuum_analyze_scale_factor = 0.01
);
ALTER TABLE chat.direct_request_retired_packages SET (
    autovacuum_vacuum_scale_factor = 0.01,
    autovacuum_analyze_scale_factor = 0.01
);
ALTER TABLE chat.group_key_package_exports SET (
    autovacuum_vacuum_scale_factor = 0.01,
    autovacuum_analyze_scale_factor = 0.01
);
ALTER TABLE chat.federated_key_package_reservations SET (
    autovacuum_vacuum_scale_factor = 0.01,
    autovacuum_analyze_scale_factor = 0.01
);
ALTER TABLE chat.conversations SET (fillfactor = 70);
