-- Migration: Sealed Historical Remote-Prefix Bootstrap Invitation Quota and Cutoff Definition
-- Target: chat.conversations, chat.enforce_invitation_quota()

SET LOCAL lock_timeout = '2s';

ALTER TABLE chat.conversations
    ADD COLUMN historical_bootstrap_last_seq BIGINT,
    ADD COLUMN historical_bootstrap_birth_xid xid8;

ALTER TABLE chat.conversations
    ADD CONSTRAINT conversations_historical_bootstrap_last_seq_check
        CHECK (
            historical_bootstrap_last_seq IS NULL
            OR (
                is_remote
                AND chat.is_safe_integer(historical_bootstrap_last_seq)
                AND historical_bootstrap_last_seq >= 1
            )
        )
        NOT VALID;

CREATE OR REPLACE FUNCTION chat.enforce_historical_bootstrap_cutoff()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    entry_count BIGINT;
    observed_first_seq BIGINT;
    observed_last_seq BIGINT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.historical_bootstrap_last_seq IS NOT NULL THEN
            RAISE EXCEPTION 'historical bootstrap cutoff must be sealed after prefix application'
                USING ERRCODE = '23514';
        END IF;
        NEW.historical_bootstrap_birth_xid :=
            CASE WHEN NEW.is_remote THEN pg_current_xact_id() ELSE NULL END;
        RETURN NEW;
    END IF;

    IF NEW.historical_bootstrap_last_seq IS NOT DISTINCT FROM OLD.historical_bootstrap_last_seq THEN
        IF NEW.historical_bootstrap_birth_xid IS DISTINCT FROM OLD.historical_bootstrap_birth_xid THEN
            RAISE EXCEPTION 'historical bootstrap birth marker is immutable'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.historical_bootstrap_last_seq IS NOT NULL
       OR NEW.historical_bootstrap_last_seq IS NULL THEN
        RAISE EXCEPTION 'historical bootstrap cutoff is immutable once sealed'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.historical_bootstrap_birth_xid IS NULL
       OR OLD.historical_bootstrap_birth_xid <> pg_current_xact_id() THEN
        RAISE EXCEPTION 'historical bootstrap cutoff may only be sealed in the birth transaction'
            USING ERRCODE = '23514';
    END IF;

    SELECT count(*), min(seq), max(seq)
      INTO entry_count, observed_first_seq, observed_last_seq
      FROM chat.entries
     WHERE conversation_id = NEW.conversation_id;

    IF entry_count <> NEW.historical_bootstrap_last_seq
       OR observed_first_seq <> 1
       OR observed_last_seq <> NEW.historical_bootstrap_last_seq
       OR NEW.next_entry_seq <> NEW.historical_bootstrap_last_seq + 1 THEN
        RAISE EXCEPTION 'historical bootstrap cutoff does not seal a contiguous prefix'
            USING ERRCODE = '23514';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM federation_sync_state
         WHERE convo_id = NEW.conversation_id::text
           AND sequencer_ds_did = NEW.sequencer_ds
           AND sequencer_term = NEW.sequencer_term
           AND last_seq = NEW.historical_bootstrap_last_seq
           AND last_epoch = NEW.current_generation
           AND last_digest IS NOT NULL
           AND status = 'healthy'
    ) THEN
        RAISE EXCEPTION 'historical bootstrap cutoff lacks matching healthy sync state'
            USING ERRCODE = '23514';
    END IF;

    NEW.historical_bootstrap_birth_xid := NULL;
    RETURN NEW;
END
$$;

CREATE TRIGGER conversations_historical_bootstrap_cutoff_insert_guard
BEFORE INSERT ON chat.conversations
FOR EACH ROW EXECUTE FUNCTION chat.enforce_historical_bootstrap_cutoff();

CREATE TRIGGER conversations_historical_bootstrap_cutoff_update_guard
BEFORE UPDATE OF historical_bootstrap_last_seq, historical_bootstrap_birth_xid
ON chat.conversations
FOR EACH ROW EXECUTE FUNCTION chat.enforce_historical_bootstrap_cutoff();

DROP TRIGGER conversations_identity_immutable ON chat.conversations;
CREATE TRIGGER conversations_identity_immutable
BEFORE UPDATE OR DELETE ON chat.conversations
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
    'lifecycle', 'current_generation', 'current_state_version', 'next_entry_seq',
    'close_transition_id', 'close_generation', 'close_state_version', 'close_seq',
    'closed_at', 'historical_bootstrap_last_seq', 'historical_bootstrap_birth_xid'
);

CREATE OR REPLACE FUNCTION chat.enforce_invitation_quota()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    pair_live_count BIGINT;
    inviter_recent_count BIGINT;
    recipient_live_count BIGINT;
    convo_remote BOOLEAN;
    convo_cutoff BIGINT;
    provenance_seq BIGINT;
    provenance_kind TEXT;
BEGIN
    -- Only newly created live pending invitations consume invitation quota. A
    -- live pending invitation is (current_membership AND status = 'pending').
    -- Acceptance (pending -> active), removal, or close can only release live
    -- counts, never add, so no UPDATE path needs to be guarded here.
    IF NOT (NEW.current_membership AND NEW.status = 'pending') THEN
        RETURN NEW;
    END IF;

    -- Historical remote-prefix bootstrap operates on an already-authenticated remote
    -- sequencer prefix with an immutable historical bootstrap cutoff. Pending
    -- invitations originating from historical creation or policy transitions at or
    -- below the cutoff are exempt from live quota enforcement.
    SELECT c.is_remote, c.historical_bootstrap_last_seq, provenance.seq, provenance.entry_kind
      INTO convo_remote, convo_cutoff, provenance_seq, provenance_kind
      FROM chat.conversations AS c
      JOIN chat.entries AS provenance
        ON provenance.conversation_id = c.conversation_id
       AND provenance.entry_id = NEW.invitation_entry_id
       AND provenance.transition_id = NEW.invitation_transition_id
     WHERE c.conversation_id = NEW.conversation_id;
    IF convo_remote
       AND convo_cutoff IS NOT NULL
       AND provenance_kind IN ('blue.catbird.chat.defs#creationEntry', 'blue.catbird.chat.defs#policyEntry')
       AND provenance_seq <= convo_cutoff THEN
        RETURN NEW;
    END IF;

    -- Serialize concurrent invitation inserts against the inviter and recipient
    -- principals so the deferred counts below are race-free (mirrors the
    -- FOR UPDATE parent-lock pattern used by the device/key-package limits).
    -- Locking in canonical DID order keeps acquisition deterministic and
    -- deadlock-free when two transactions touch the same DIDs in opposite roles.
    PERFORM 1 FROM chat.principals
     WHERE user_did IN (NEW.created_by_did, NEW.user_did)
     ORDER BY user_did
     FOR UPDATE;

    -- Limit 1: at most 5 live pending invitations per (inviterDid, recipientDid)
    -- pair, across all conversations.
    SELECT count(*) INTO pair_live_count
      FROM chat.participants
     WHERE created_by_did = NEW.created_by_did
       AND user_did = NEW.user_did
       AND current_membership
       AND status = 'pending';
    IF pair_live_count > 5 THEN
        RAISE EXCEPTION 'invitation limit reached: at most 5 live pending invitations per (inviter, recipient) pair'
            USING ERRCODE = '23514';
    END IF;

    -- Limit 2: at most 100 newly created pending invitations per inviter in a
    -- rolling 24 hours. This is a creation-rate cap, so it counts every
    -- invitation row this inviter created in the window regardless of current
    -- status (acceptance or removal does not refund the daily creation budget).
    SELECT count(*) INTO inviter_recent_count
      FROM chat.participants
     WHERE created_by_did = NEW.created_by_did
       AND invitation_transition_id IS NOT NULL
       AND created_at >= now() - INTERVAL '24 hours';
    IF inviter_recent_count > 100 THEN
        RAISE EXCEPTION 'invitation limit reached: at most 100 newly created pending invitations per inviter per rolling 24h'
            USING ERRCODE = '23514';
    END IF;

    -- Limit 3: at most 100 live pending invitations per recipient, across all
    -- conversations.
    SELECT count(*) INTO recipient_live_count
      FROM chat.participants
     WHERE user_did = NEW.user_did
       AND current_membership
       AND status = 'pending';
    IF recipient_live_count > 100 THEN
        RAISE EXCEPTION 'invitation limit reached: at most 100 live pending invitations per recipient'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END
$$;
