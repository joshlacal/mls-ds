-- Drop plaintext group metadata. Authoritative metadata lives in
-- group_metadata_blobs (encrypted) and is fetched/decrypted client-side
-- via blue.catbird.mlsChat.getGroupMetadataBlob.
--
-- Phase E of the MLS metadata cutover (see
-- docs/MLS_CLIENT_PROTOCOL.md and the workspace plan
-- ok-we-need-to-splendid-goblet.md). After this migration:
--   * conversations.{name, description} columns no longer exist
--   * `active_invites` and `conversation_policy_summary` views are
--     recreated without `c.name as conversation_name`
--
-- Views must be dropped first because they depend on the columns being
-- removed; ALTER TABLE ... DROP COLUMN would otherwise fail with
-- "cannot drop column ... because other objects depend on it".

DROP VIEW IF EXISTS active_invites;
DROP VIEW IF EXISTS conversation_policy_summary;

ALTER TABLE conversations DROP COLUMN IF EXISTS name;
ALTER TABLE conversations DROP COLUMN IF EXISTS description;

-- Recreate views without c.name. Bytes-for-bytes identical to the
-- post-edit `schema_greenfield.sql` definitions (modulo the dropped
-- `c.name as conversation_name` columns and the `c.name` GROUP BY
-- entry).

CREATE OR REPLACE VIEW active_invites AS
SELECT
    i.id,
    i.convo_id,
    i.created_by_did,
    i.target_did,
    i.created_at,
    i.expires_at,
    i.max_uses,
    i.uses_count,
    CASE
        WHEN i.max_uses IS NOT NULL THEN i.max_uses - i.uses_count
        ELSE NULL
    END as remaining_uses
FROM invites i
JOIN conversations c ON i.convo_id = c.id
WHERE i.revoked = false
  AND (i.expires_at IS NULL OR i.expires_at > NOW())
  AND (i.max_uses IS NULL OR i.uses_count < i.max_uses);

COMMENT ON VIEW active_invites IS 'Shows all currently usable invites with remaining uses';

CREATE OR REPLACE VIEW conversation_policy_summary AS
SELECT
    c.id as convo_id,
    c.creator_did,
    p.allow_external_commits,
    p.require_invite_for_join,
    p.allow_rejoin,
    p.rejoin_window_days,
    p.prevent_removing_last_admin,
    p.updated_at as policy_updated_at,
    COUNT(DISTINCT m.member_did) FILTER (WHERE m.left_at IS NULL) as member_count,
    COUNT(DISTINCT m.member_did) FILTER (WHERE m.is_admin = true AND m.left_at IS NULL) as admin_count,
    COUNT(DISTINCT i.id) FILTER (WHERE
        i.revoked = false
        AND (i.expires_at IS NULL OR i.expires_at > NOW())
        AND (i.max_uses IS NULL OR i.uses_count < i.max_uses)
    ) as active_invite_count
FROM conversations c
LEFT JOIN conversation_policy p ON c.id = p.convo_id
LEFT JOIN members m ON c.id = m.convo_id
LEFT JOIN invites i ON c.id = i.convo_id
GROUP BY c.id, c.creator_did, p.allow_external_commits, p.require_invite_for_join,
         p.allow_rejoin, p.rejoin_window_days, p.prevent_removing_last_admin, p.updated_at;

COMMENT ON VIEW conversation_policy_summary IS 'Summary view of conversations with their policies and stats';
