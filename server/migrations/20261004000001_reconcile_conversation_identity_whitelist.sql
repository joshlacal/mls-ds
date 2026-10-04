-- Migration: reconcile chat.conversations mutable-column whitelist after the
-- main + encrypted-requests line merge (integration/clean-chat-merge-20261004).
--
-- Both lines rebuilt the same identity trigger with different whitelists:
--   * 20260828000001_chat_historical_bootstrap_quota (main) added
--     historical_bootstrap_last_seq and historical_bootstrap_birth_xid;
--   * 20260919000002_direct_request_publication (encrypted-requests) added
--     protocol_version, but rebuilt the trigger from the pre-main list and so
--     silently re-froze main's two historical-bootstrap columns.
-- Applied in timestamp order on a fresh database the later rebuild wins, which
-- makes every historical-bootstrap head update fail as an identity change.
-- Neither existing migration is edited (either may already be applied); this
-- one restores the exact union. It is re-appliable: the trigger is dropped
-- with IF EXISTS before being recreated.

DROP TRIGGER IF EXISTS conversations_identity_immutable ON chat.conversations;
CREATE TRIGGER conversations_identity_immutable
BEFORE UPDATE OR DELETE ON chat.conversations
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
    'lifecycle', 'current_generation', 'current_state_version', 'next_entry_seq',
    'close_transition_id', 'close_generation', 'close_state_version', 'close_seq',
    'closed_at', 'historical_bootstrap_last_seq', 'historical_bootstrap_birth_xid',
    'protocol_version'
);
