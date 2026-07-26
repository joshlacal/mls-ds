-- Give every superseded Welcome one durable, directly loadable terminal cause.
--
-- A transition stores the public prior coordinate as
-- (conversation_id, prior_generation, prior_state_version). Its deferred
-- transitions_prior_state_fk binds that tuple to the unique generation_states
-- row, which carries the remaining crypto coordinate. The backfill and COMMIT
-- assertion therefore compare the Welcome bundle to that exact state row; they
-- never infer a cause from timestamps or from generation/stateVersion alone.

ALTER TABLE chat.welcome_dispositions
    ADD COLUMN IF NOT EXISTS terminal_transition_id UUID;
ALTER TABLE chat.welcome_dispositions
    ADD COLUMN IF NOT EXISTS terminal_revocation_id UUID;

-- Existing disposition rows are immutable. Temporarily remove the trigger only
-- inside this transactional migration so the exact-one durable-fact backfill can
-- populate the new provenance columns.
DROP TRIGGER IF EXISTS welcome_dispositions_immutable
    ON chat.welcome_dispositions;

DO $$
DECLARE
    ambiguous_rows BIGINT;
BEGIN
    WITH transition_candidates AS (
        SELECT disposition.welcome_id,
               transition_row.transition_id AS source_id,
               'transition'::TEXT AS source_kind
          FROM chat.welcome_dispositions disposition
          JOIN chat.welcome_deliveries delivery
            ON delivery.welcome_id = disposition.welcome_id
          JOIN chat.welcome_bundles bundle
            ON bundle.welcome_id = disposition.welcome_id
          JOIN chat.transitions transition_row
            ON transition_row.conversation_id = bundle.conversation_id
           AND transition_row.prior_generation = bundle.generation
           AND transition_row.prior_state_version = bundle.state_version
           AND transition_row.entry_seq > bundle.entry_seq
           AND transition_row.accepted_at = disposition.terminal_at
           AND (transition_row.next_generation, transition_row.next_state_version)
               IS DISTINCT FROM (bundle.generation, bundle.state_version)
          JOIN chat.generation_states prior_state
            ON prior_state.conversation_id = transition_row.conversation_id
           AND prior_state.generation = transition_row.prior_generation
           AND prior_state.state_version = transition_row.prior_state_version
           AND prior_state.group_id = bundle.group_id
           AND prior_state.epoch = bundle.epoch
           AND prior_state.group_context_hash = bundle.group_context_hash
           AND prior_state.confirmation_tag = bundle.confirmation_tag
         WHERE disposition.winner_kind = 'superseded'
    ),
    revocation_candidates AS (
        SELECT disposition.welcome_id,
               revocation.revocation_id AS source_id,
               'revocation'::TEXT AS source_kind
          FROM chat.welcome_dispositions disposition
          JOIN chat.welcome_deliveries delivery
            ON delivery.welcome_id = disposition.welcome_id
          JOIN chat.device_revocations revocation
            ON revocation.target_did = delivery.recipient_did
           AND revocation.target_device_id = delivery.recipient_device_id
           AND revocation.accepted_at = disposition.terminal_at
         WHERE disposition.winner_kind = 'superseded'
    ),
    candidates AS (
        SELECT * FROM transition_candidates
        UNION ALL
        SELECT * FROM revocation_candidates
    ),
    candidate_counts AS (
        SELECT disposition.welcome_id, count(candidate.source_id) AS candidate_count
          FROM chat.welcome_dispositions disposition
          LEFT JOIN candidates candidate
            ON candidate.welcome_id = disposition.welcome_id
         WHERE disposition.winner_kind = 'superseded'
         GROUP BY disposition.welcome_id
    )
    SELECT count(*) INTO ambiguous_rows
      FROM candidate_counts
     WHERE candidate_count <> 1;

    IF ambiguous_rows <> 0 THEN
        RAISE EXCEPTION
            'Welcome supersession provenance backfill requires exactly one durable cause; % row(s) have zero or multiple candidates',
            ambiguous_rows
            USING ERRCODE = '23514';
    END IF;
END
$$;

WITH transition_candidates AS (
    SELECT disposition.welcome_id,
           transition_row.transition_id AS source_id,
           'transition'::TEXT AS source_kind
      FROM chat.welcome_dispositions disposition
      JOIN chat.welcome_deliveries delivery
        ON delivery.welcome_id = disposition.welcome_id
      JOIN chat.welcome_bundles bundle
        ON bundle.welcome_id = disposition.welcome_id
      JOIN chat.transitions transition_row
        ON transition_row.conversation_id = bundle.conversation_id
       AND transition_row.prior_generation = bundle.generation
       AND transition_row.prior_state_version = bundle.state_version
       AND transition_row.entry_seq > bundle.entry_seq
       AND transition_row.accepted_at = disposition.terminal_at
       AND (transition_row.next_generation, transition_row.next_state_version)
           IS DISTINCT FROM (bundle.generation, bundle.state_version)
      JOIN chat.generation_states prior_state
        ON prior_state.conversation_id = transition_row.conversation_id
       AND prior_state.generation = transition_row.prior_generation
       AND prior_state.state_version = transition_row.prior_state_version
       AND prior_state.group_id = bundle.group_id
       AND prior_state.epoch = bundle.epoch
       AND prior_state.group_context_hash = bundle.group_context_hash
       AND prior_state.confirmation_tag = bundle.confirmation_tag
     WHERE disposition.winner_kind = 'superseded'
),
revocation_candidates AS (
    SELECT disposition.welcome_id,
           revocation.revocation_id AS source_id,
           'revocation'::TEXT AS source_kind
      FROM chat.welcome_dispositions disposition
      JOIN chat.welcome_deliveries delivery
        ON delivery.welcome_id = disposition.welcome_id
      JOIN chat.device_revocations revocation
        ON revocation.target_did = delivery.recipient_did
       AND revocation.target_device_id = delivery.recipient_device_id
       AND revocation.accepted_at = disposition.terminal_at
     WHERE disposition.winner_kind = 'superseded'
),
candidates AS (
    SELECT * FROM transition_candidates
    UNION ALL
    SELECT * FROM revocation_candidates
)
UPDATE chat.welcome_dispositions disposition
   SET terminal_transition_id = CASE candidate.source_kind
           WHEN 'transition' THEN candidate.source_id
           ELSE NULL
       END,
       terminal_revocation_id = CASE candidate.source_kind
           WHEN 'revocation' THEN candidate.source_id
           ELSE NULL
       END
  FROM candidates candidate
 WHERE disposition.welcome_id = candidate.welcome_id
   AND disposition.winner_kind = 'superseded';

UPDATE chat.welcome_dispositions
   SET terminal_transition_id = NULL,
       terminal_revocation_id = NULL
 WHERE winner_kind <> 'superseded';

CREATE TRIGGER welcome_dispositions_immutable
BEFORE UPDATE OR DELETE ON chat.welcome_dispositions
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid = 'chat.welcome_dispositions'::regclass
           AND conname = 'welcome_dispositions_terminal_source_shape_check'
    ) THEN
        ALTER TABLE chat.welcome_dispositions
            ADD CONSTRAINT welcome_dispositions_terminal_source_shape_check
            CHECK (
                (winner_kind = 'superseded'
                    AND num_nonnulls(
                        terminal_transition_id,
                        terminal_revocation_id
                    ) = 1)
                OR (winner_kind <> 'superseded'
                    AND terminal_transition_id IS NULL
                    AND terminal_revocation_id IS NULL)
            );
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid = 'chat.welcome_dispositions'::regclass
           AND conname = 'welcome_dispositions_terminal_transition_fk'
    ) THEN
        ALTER TABLE chat.welcome_dispositions
            ADD CONSTRAINT welcome_dispositions_terminal_transition_fk
            FOREIGN KEY (terminal_transition_id)
            REFERENCES chat.transitions(transition_id)
            DEFERRABLE INITIALLY DEFERRED;
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid = 'chat.welcome_dispositions'::regclass
           AND conname = 'welcome_dispositions_terminal_revocation_fk'
    ) THEN
        ALTER TABLE chat.welcome_dispositions
            ADD CONSTRAINT welcome_dispositions_terminal_revocation_fk
            FOREIGN KEY (terminal_revocation_id)
            REFERENCES chat.device_revocations(revocation_id)
            DEFERRABLE INITIALLY DEFERRED;
    END IF;
END
$$;

-- Preserve the existing delivery/event/recipient/outbox/status/time CAS checks
-- and add an exact selected-source proof. A transition source must consume the
-- Welcome bundle's exact prior public coordinate via generation_states, occur at
-- a later entry seq, change the public coordinate, and have accepted_at equal to
-- terminal_at. A revocation source must target the exact recipient device at the
-- same terminal instant.
CREATE OR REPLACE FUNCTION chat.assert_welcome_disposition_cas(target_welcome UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    delivery_row chat.welcome_deliveries%ROWTYPE;
    disposition_count BIGINT;
BEGIN
    SELECT * INTO delivery_row
      FROM chat.welcome_deliveries
     WHERE welcome_id = target_welcome;
    IF NOT FOUND THEN
        IF EXISTS (
            SELECT 1 FROM chat.welcome_dispositions
             WHERE welcome_id = target_welcome
        ) THEN
            RAISE EXCEPTION 'Welcome disposition CAS mismatch'
                USING ERRCODE = '23514';
        END IF;
        RETURN;
    END IF;

    PERFORM 1
      FROM chat.welcome_bundles bundle
      JOIN chat.conversations conversation
        ON conversation.conversation_id = bundle.conversation_id
     WHERE bundle.welcome_id = target_welcome
     FOR UPDATE OF conversation;
    SELECT count(*) INTO disposition_count
      FROM chat.welcome_dispositions
     WHERE welcome_id = target_welcome;

    IF delivery_row.status = 'pending' THEN
        IF disposition_count <> 0 THEN
            RAISE EXCEPTION 'pending Welcome has terminal disposition'
                USING ERRCODE = '23514';
        END IF;
    ELSIF disposition_count <> 1 OR NOT EXISTS (
        SELECT 1
          FROM chat.welcome_dispositions disposition
          JOIN chat.events event
            ON event.event_position = disposition.event_position
         WHERE disposition.welcome_id = target_welcome
           AND disposition.winner_kind = delivery_row.status
           AND disposition.terminal_at = delivery_row.terminal_at
           AND event.event_kind = 'welcomeDisposition'
           AND event.created_at = delivery_row.terminal_at
           AND EXISTS (
                SELECT 1
                  FROM chat.event_recipients recipient
                 WHERE recipient.event_position = event.event_position
                   AND recipient.user_did = delivery_row.recipient_did
                   AND recipient.device_id = delivery_row.recipient_device_id
                   AND recipient.entitlement_kind = 'welcome'
           )
           AND EXISTS (
                SELECT 1
                  FROM chat.outbox work
                 WHERE work.event_position = event.event_position
                   AND work.work_kind = 'stream'
           )
           AND (
                (disposition.winner_kind <> 'superseded'
                    AND disposition.terminal_transition_id IS NULL
                    AND disposition.terminal_revocation_id IS NULL)
                OR (
                    disposition.winner_kind = 'superseded'
                    AND disposition.terminal_transition_id IS NOT NULL
                    AND disposition.terminal_revocation_id IS NULL
                    AND EXISTS (
                        SELECT 1
                          FROM chat.welcome_bundles bundle
                          JOIN chat.transitions transition_row
                            ON transition_row.transition_id =
                                disposition.terminal_transition_id
                           AND transition_row.conversation_id =
                                bundle.conversation_id
                           AND transition_row.prior_generation =
                                bundle.generation
                           AND transition_row.prior_state_version =
                                bundle.state_version
                           AND transition_row.entry_seq > bundle.entry_seq
                           AND transition_row.accepted_at =
                                disposition.terminal_at
                           AND (
                                transition_row.next_generation,
                                transition_row.next_state_version
                           ) IS DISTINCT FROM (
                                bundle.generation,
                                bundle.state_version
                           )
                          JOIN chat.generation_states prior_state
                            ON prior_state.conversation_id =
                                transition_row.conversation_id
                           AND prior_state.generation =
                                transition_row.prior_generation
                           AND prior_state.state_version =
                                transition_row.prior_state_version
                           AND prior_state.group_id = bundle.group_id
                           AND prior_state.epoch = bundle.epoch
                           AND prior_state.group_context_hash =
                                bundle.group_context_hash
                           AND prior_state.confirmation_tag =
                                bundle.confirmation_tag
                         WHERE bundle.welcome_id = disposition.welcome_id
                    )
                )
                OR (
                    disposition.winner_kind = 'superseded'
                    AND disposition.terminal_transition_id IS NULL
                    AND disposition.terminal_revocation_id IS NOT NULL
                    AND EXISTS (
                        SELECT 1
                          FROM chat.device_revocations revocation
                         WHERE revocation.revocation_id =
                                disposition.terminal_revocation_id
                           AND revocation.target_did =
                                delivery_row.recipient_did
                           AND revocation.target_device_id =
                                delivery_row.recipient_device_id
                           AND revocation.accepted_at =
                                disposition.terminal_at
                    )
                )
           )
    ) THEN
        RAISE EXCEPTION 'terminal Welcome disposition mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;
