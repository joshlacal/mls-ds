-- Wave 2 (`W2-D`):
-- 1. Cross-device enrollment approval (`pending_approval` device status, `blue.catbird.chat.approveDevice`,
--    `chat.device_approvals` provenance table, operation claim / idempotency / DPoP constraints).
-- 2. Nov-12 ATProto Spaces (`atproto#5187`) `SpaceHost` operational schema:
--    - `chat.conversation_space_writers`: `prev_space_rev`, `removed_at` (`#repoRemoved` tombstones)
--    - `chat.conversation_space_subscribers`: inline `authorizeSpaceSync` `notify` registrations
--      with `confirmed` challenge state and `notified_expired` tracking
--    - `chat.managed_space_members`: batched `com.atproto.memberspace.{putMembers,removeMembers,listMembers}`
--      and `com.atproto.managedspace.checkAccess` explicit member ACLs
--    - `chat.conversation_space_records`: hosted writer records for `com.atproto.space.{getRecord,getRepo}`
--      (`STAR` v0.2 `application/vnd.dasl.star` & `Atproto-Space-Record` MAC).

LOCK TABLE chat.devices, chat.dpop_replays, chat.operation_claims, chat.idempotency_records
    IN ACCESS EXCLUSIVE MODE;

-- 1. `chat.devices`: add `'pending_approval'` lifecycle state (`D-2`).
ALTER TABLE chat.devices
    DROP CONSTRAINT IF EXISTS devices_status_check,
    ADD CONSTRAINT devices_status_check
        CHECK (status IN ('active', 'pending_approval', 'revoked')),
    DROP CONSTRAINT IF EXISTS devices_revocation_shape_check,
    ADD CONSTRAINT devices_revocation_shape_check CHECK (
        (status IN ('active', 'pending_approval')
            AND revoked_at IS NULL
            AND revocation_id IS NULL)
        OR (status = 'revoked'
            AND revoked_at IS NOT NULL
            AND chat.is_uuid_v4(revocation_id))
    );

DROP INDEX IF EXISTS chat.devices_active_dpop_jkt_uq;
CREATE UNIQUE INDEX devices_active_dpop_jkt_uq
    ON chat.devices (user_did, dpop_jkt)
    WHERE status IN ('active', 'pending_approval');

CREATE OR REPLACE FUNCTION chat.enforce_device_auth_lifecycle_transition()
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
       OR (OLD.status = 'active' AND NEW.status NOT IN ('active', 'revoked'))
       OR (OLD.status = 'pending_approval'
           AND NEW.status NOT IN ('pending_approval', 'active', 'revoked')) THEN
        RAISE EXCEPTION 'invalid device lifecycle transition' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

-- 2. Operation claims, idempotency records, and DPoP replay endpoint allowlists for `approveDevice`.
CREATE OR REPLACE FUNCTION chat.operation_mutation_kind_from_transcript(transcript BYTEA)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT CASE
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-DEVICE-ENROLL') THEN 'blue.catbird.chat.defs#deviceEnrollmentBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-DEVICE-APPROVE') THEN 'blue.catbird.chat.defs#deviceApprovalBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-DEVICE-REPLENISH') THEN 'blue.catbird.chat.defs#keyPackageReplenishmentBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-DEVICE-REBIND') THEN 'blue.catbird.chat.defs#deviceAuthenticationRebindBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-DEVICE-REVOKE') THEN 'blue.catbird.chat.defs#deviceRevocationBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-BLOB-PREPARE') THEN 'blue.catbird.chat.defs#blobUploadPreparationBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-BLOB-DELETE') THEN 'blue.catbird.chat.defs#blobDeletionBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-CREATE') THEN 'blue.catbird.chat.defs#creationBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-COMMIT') THEN 'blue.catbird.chat.defs#commitTransitionBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-POLICY') THEN 'blue.catbird.chat.defs#policyTransitionBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-ACCEPT') THEN 'blue.catbird.chat.defs#participantAcceptanceBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-MESSAGE') THEN 'blue.catbird.chat.defs#applicationSendBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-TYPING') THEN 'blue.catbird.chat.defs#typingBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-METADATA') THEN 'blue.catbird.chat.defs#metadataTransitionBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-RESET-REQUEST') THEN 'blue.catbird.chat.defs#resetRequestBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-RESET-ACTIVATE') THEN 'blue.catbird.chat.defs#resetActivationBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-LEAF-RECOVERY-REQUEST') THEN 'blue.catbird.chat.defs#leafRecoveryRequestBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-LEAF-RECOVERY-CANCEL') THEN 'blue.catbird.chat.defs#leafRecoveryCancellationBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-LEAF-RECOVERY-FULFILL') THEN 'blue.catbird.chat.defs#leafRecoveryFulfillmentBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-CLOSE') THEN 'blue.catbird.chat.defs#conversationCloseBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-LEAVE-REQUEST') THEN 'blue.catbird.chat.defs#leaveRequestBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-LEAVE-ZERO-LEAF') THEN 'blue.catbird.chat.defs#zeroLeafLeaveBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-LEAVE-CANCEL') THEN 'blue.catbird.chat.defs#leaveCancellationBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-LEAVE-FULFILL-COMMIT') THEN 'blue.catbird.chat.defs#leaveCommitFulfillmentBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-WELCOME-ACK') THEN 'blue.catbird.chat.defs#welcomeAcknowledgementBody'
        WHEN chat.transcript_has_exact_domain(transcript,'CATBIRD-CHAT-WELCOME-REJECT') THEN 'blue.catbird.chat.defs#welcomeRejectionBody'
        ELSE NULL
    END
$$;

CREATE OR REPLACE FUNCTION chat.operation_mutation_kind_from_wrapper(wrapper BYTEA)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    exact_type TEXT := chat.exact_wrapper_body_type(wrapper);
BEGIN
    RETURN CASE
        WHEN exact_type = 'blue.catbird.chat.defs#deviceEnrollmentBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#deviceApprovalBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#keyPackageReplenishmentBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#deviceAuthenticationRebindBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#deviceRevocationBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#blobUploadPreparationBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#blobDeletionBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#creationBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#commitTransitionBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#policyTransitionBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#participantAcceptanceBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#applicationSendBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#typingBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#metadataTransitionBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#resetRequestBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#resetActivationBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#leafRecoveryRequestBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#leafRecoveryCancellationBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#leafRecoveryFulfillmentBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#conversationCloseBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#leaveRequestBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#zeroLeafLeaveBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#leaveCancellationBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#leaveCommitFulfillmentBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#welcomeAcknowledgementBody' THEN exact_type
        WHEN exact_type = 'blue.catbird.chat.defs#welcomeRejectionBody' THEN exact_type
        ELSE NULL
    END;
END
$$;

CREATE OR REPLACE FUNCTION chat.operation_endpoint_accepts_kind(endpoint TEXT, kind TEXT)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT CASE endpoint
        WHEN 'blue.catbird.chat.acceptConversation' THEN kind = 'blue.catbird.chat.defs#participantAcceptanceBody'
        WHEN 'blue.catbird.chat.acknowledgeWelcome' THEN kind = 'blue.catbird.chat.defs#welcomeAcknowledgementBody'
        WHEN 'blue.catbird.chat.activateReset' THEN kind = 'blue.catbird.chat.defs#resetActivationBody'
        WHEN 'blue.catbird.chat.approveDevice' THEN kind = 'blue.catbird.chat.defs#deviceApprovalBody'
        WHEN 'blue.catbird.chat.cancelLeafRecovery' THEN kind = 'blue.catbird.chat.defs#leafRecoveryCancellationBody'
        WHEN 'blue.catbird.chat.cancelLeave' THEN kind = 'blue.catbird.chat.defs#leaveCancellationBody'
        WHEN 'blue.catbird.chat.closeConversation' THEN kind = 'blue.catbird.chat.defs#conversationCloseBody'
        WHEN 'blue.catbird.chat.createConversation' THEN kind = 'blue.catbird.chat.defs#creationBody'
        WHEN 'blue.catbird.chat.deleteBlob' THEN kind = 'blue.catbird.chat.defs#blobDeletionBody'
        WHEN 'blue.catbird.chat.enrollDevice' THEN kind = 'blue.catbird.chat.defs#deviceEnrollmentBody'
        WHEN 'blue.catbird.chat.prepareBlobUpload' THEN kind = 'blue.catbird.chat.defs#blobUploadPreparationBody'
        WHEN 'blue.catbird.chat.rebindDeviceAuthentication' THEN kind = 'blue.catbird.chat.defs#deviceAuthenticationRebindBody'
        WHEN 'blue.catbird.chat.rejectWelcome' THEN kind = 'blue.catbird.chat.defs#welcomeRejectionBody'
        WHEN 'blue.catbird.chat.replenishKeyPackages' THEN kind = 'blue.catbird.chat.defs#keyPackageReplenishmentBody'
        WHEN 'blue.catbird.chat.requestLeafRecovery' THEN kind = 'blue.catbird.chat.defs#leafRecoveryRequestBody'
        WHEN 'blue.catbird.chat.requestLeave' THEN kind = ANY (ARRAY[
            'blue.catbird.chat.defs#leaveRequestBody',
            'blue.catbird.chat.defs#zeroLeafLeaveBody'
        ])
        WHEN 'blue.catbird.chat.requestReset' THEN kind = 'blue.catbird.chat.defs#resetRequestBody'
        WHEN 'blue.catbird.chat.revokeDevice' THEN kind = 'blue.catbird.chat.defs#deviceRevocationBody'
        WHEN 'blue.catbird.chat.sendMessage' THEN kind = 'blue.catbird.chat.defs#applicationSendBody'
        WHEN 'blue.catbird.chat.publishTyping' THEN kind = 'blue.catbird.chat.defs#typingBody'
        WHEN 'blue.catbird.chat.submitTransition' THEN kind = ANY (ARRAY[
            'blue.catbird.chat.defs#commitTransitionBody',
            'blue.catbird.chat.defs#policyTransitionBody',
            'blue.catbird.chat.defs#metadataTransitionBody',
            'blue.catbird.chat.defs#leafRecoveryFulfillmentBody',
            'blue.catbird.chat.defs#leaveCommitFulfillmentBody'
        ])
        ELSE FALSE
    END
$$;

ALTER TABLE chat.dpop_replays
    DROP CONSTRAINT IF EXISTS dpop_replays_lxm_check,
    ADD CONSTRAINT dpop_replays_lxm_check CHECK (
        lxm = ANY (ARRAY[
            'blue.catbird.chat.acceptConversation',
            'blue.catbird.chat.acknowledgeWelcome',
            'blue.catbird.chat.activateReset',
            'blue.catbird.chat.approveDevice',
            'blue.catbird.chat.cancelLeafRecovery',
            'blue.catbird.chat.cancelLeave',
            'blue.catbird.chat.closeConversation',
            'blue.catbird.chat.createConversation',
            'blue.catbird.chat.deleteBlob',
            'blue.catbird.chat.enrollDevice',
            'blue.catbird.chat.getBlob',
            'blue.catbird.chat.getBlobUsage',
            'blue.catbird.chat.getConversationState',
            'blue.catbird.chat.getConversations',
            'blue.catbird.chat.getDevices',
            'blue.catbird.chat.getEntries',
            'blue.catbird.chat.getLeafRecoveryInbox',
            'blue.catbird.chat.getOwnDevices',
            'blue.catbird.chat.getPendingWelcomes',
            'blue.catbird.chat.getSubscriptionTicket',
            'blue.catbird.chat.prepareBlobUpload',
            'blue.catbird.chat.publishTyping',
            'blue.catbird.chat.rebindDeviceAuthentication',
            'blue.catbird.chat.rejectWelcome',
            'blue.catbird.chat.replenishKeyPackages',
            'blue.catbird.chat.requestLeafRecovery',
            'blue.catbird.chat.requestLeave',
            'blue.catbird.chat.requestReset',
            'blue.catbird.chat.revokeDevice',
            'blue.catbird.chat.sendMessage',
            'blue.catbird.chat.submitTransition',
            'blue.catbird.chat.uploadBlob'
        ])
    );

ALTER TABLE chat.operation_claims
    DROP CONSTRAINT IF EXISTS operation_claims_endpoint_check,
    ADD CONSTRAINT operation_claims_endpoint_check CHECK (
        endpoint_nsid = ANY (ARRAY[
            'blue.catbird.chat.acceptConversation',
            'blue.catbird.chat.acknowledgeWelcome',
            'blue.catbird.chat.activateReset',
            'blue.catbird.chat.approveDevice',
            'blue.catbird.chat.cancelLeafRecovery',
            'blue.catbird.chat.cancelLeave',
            'blue.catbird.chat.closeConversation',
            'blue.catbird.chat.createConversation',
            'blue.catbird.chat.deleteBlob',
            'blue.catbird.chat.enrollDevice',
            'blue.catbird.chat.prepareBlobUpload',
            'blue.catbird.chat.rebindDeviceAuthentication',
            'blue.catbird.chat.rejectWelcome',
            'blue.catbird.chat.replenishKeyPackages',
            'blue.catbird.chat.requestLeafRecovery',
            'blue.catbird.chat.requestLeave',
            'blue.catbird.chat.requestReset',
            'blue.catbird.chat.revokeDevice',
            'blue.catbird.chat.sendMessage',
            'blue.catbird.chat.submitTransition'
        ])
    );

ALTER TABLE chat.idempotency_records
    DROP CONSTRAINT IF EXISTS idempotency_records_endpoint_check,
    ADD CONSTRAINT idempotency_records_endpoint_check CHECK (
        endpoint_nsid = ANY (ARRAY[
            'blue.catbird.chat.acceptConversation',
            'blue.catbird.chat.acknowledgeWelcome',
            'blue.catbird.chat.activateReset',
            'blue.catbird.chat.approveDevice',
            'blue.catbird.chat.cancelLeafRecovery',
            'blue.catbird.chat.cancelLeave',
            'blue.catbird.chat.closeConversation',
            'blue.catbird.chat.createConversation',
            'blue.catbird.chat.deleteBlob',
            'blue.catbird.chat.enrollDevice',
            'blue.catbird.chat.prepareBlobUpload',
            'blue.catbird.chat.rebindDeviceAuthentication',
            'blue.catbird.chat.rejectWelcome',
            'blue.catbird.chat.replenishKeyPackages',
            'blue.catbird.chat.requestLeafRecovery',
            'blue.catbird.chat.requestLeave',
            'blue.catbird.chat.requestReset',
            'blue.catbird.chat.revokeDevice',
            'blue.catbird.chat.sendMessage',
            'blue.catbird.chat.submitTransition'
        ])
    );

-- 3. `chat.device_approvals`: immutable cross-device enrollment approval provenance (`D-2`).
CREATE TABLE chat.device_approvals (
    approval_id UUID PRIMARY KEY,
    actor_did TEXT NOT NULL,
    actor_device_id UUID NOT NULL,
    actor_key_id TEXT NOT NULL,
    actor_auth_generation BIGINT NOT NULL,
    target_did TEXT NOT NULL,
    target_device_id UUID NOT NULL,
    target_key_id TEXT NOT NULL,
    target_signing_public_key BYTEA NOT NULL,
    target_auth_generation BIGINT NOT NULL,
    accepted_request_bytes BYTEA NOT NULL,
    signing_transcript_bytes BYTEA NOT NULL,
    request_digest BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    signed_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT device_approvals_actor_key_fk FOREIGN KEY (
        actor_did, actor_device_id, actor_key_id
    ) REFERENCES chat.device_keys(user_did, device_id, key_id),
    CONSTRAINT device_approvals_target_key_fk FOREIGN KEY (
        target_did, target_device_id, target_key_id, target_signing_public_key
    ) REFERENCES chat.device_keys(user_did, device_id, key_id, signing_public_key),
    CONSTRAINT device_approvals_id_check CHECK (chat.is_uuid_v4(approval_id)),
    CONSTRAINT device_approvals_same_principal_check CHECK (
        actor_did = target_did AND chat.is_bare_did(actor_did)
    ),
    CONSTRAINT device_approvals_distinct_devices_check CHECK (
        chat.is_uuid_v4(actor_device_id)
        AND chat.is_uuid_v4(target_device_id)
        AND actor_device_id <> target_device_id
    ),
    CONSTRAINT device_approvals_key_check CHECK (
        chat.is_base64url_sha256(actor_key_id)
        AND chat.is_base64url_sha256(target_key_id)
        AND octet_length(target_signing_public_key) = 32
    ),
    CONSTRAINT device_approvals_generation_check CHECK (
        chat.is_safe_integer(actor_auth_generation) AND actor_auth_generation >= 1
        AND chat.is_safe_integer(target_auth_generation) AND target_auth_generation >= 1
    ),
    CONSTRAINT device_approvals_signature_check CHECK (
        octet_length(accepted_request_bytes) BETWEEN 1 AND 16777216
        AND octet_length(signing_transcript_bytes) BETWEEN 1 AND 16777216
        AND octet_length(request_digest) = 32
        AND request_digest = digest(signing_transcript_bytes, 'sha256')
        AND octet_length(signature) = 64
    ),
    CONSTRAINT device_approvals_time_check CHECK (
        signed_at BETWEEN accepted_at - INTERVAL '5 minutes'
                      AND accepted_at + INTERVAL '60 seconds'
    ),
    CONSTRAINT device_approvals_target_uq UNIQUE (target_did, target_device_id)
);

CREATE TRIGGER device_approvals_immutable
BEFORE UPDATE OR DELETE ON chat.device_approvals
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity();

-- 4. Nov-12 `SpaceHost` schema (`atproto#5187`).
ALTER TABLE chat.conversation_space_writers
    ADD COLUMN IF NOT EXISTS prev_space_rev TEXT,
    ADD COLUMN IF NOT EXISTS removed_at TIMESTAMPTZ,
    ALTER COLUMN repo_rev DROP NOT NULL,
    ALTER COLUMN data_cid DROP NOT NULL,
    DROP CONSTRAINT IF EXISTS conversation_space_writers_data_cid_check,
    ADD CONSTRAINT conversation_space_writers_event_shape_check CHECK (
        (removed_at IS NULL
            AND repo_rev IS NOT NULL
            AND data_cid IS NOT NULL
            AND octet_length(data_cid) = 32)
        OR (removed_at IS NOT NULL
            AND repo_rev IS NULL
            AND data_cid IS NULL)
    );

CREATE TABLE IF NOT EXISTS chat.conversation_space_subscribers (
    space_uri TEXT NOT NULL REFERENCES chat.conversation_spaces(space_uri) ON DELETE CASCADE,
    endpoint_url TEXT NOT NULL,
    token TEXT NOT NULL CHECK (octet_length(token) BETWEEN 1 AND 1024),
    expires_at TIMESTAMPTZ NOT NULL,
    confirmed BOOLEAN NOT NULL DEFAULT TRUE,
    notified_expired BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (space_uri, endpoint_url, token)
);

CREATE INDEX IF NOT EXISTS conversation_space_subscribers_space_idx
    ON chat.conversation_space_subscribers (space_uri, expires_at);

CREATE TABLE IF NOT EXISTS chat.managed_space_members (
    space_uri TEXT NOT NULL REFERENCES chat.conversation_spaces(space_uri) ON DELETE CASCADE,
    member_did TEXT NOT NULL,
    can_read BOOLEAN NOT NULL,
    can_write BOOLEAN NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (space_uri, member_did),
    CONSTRAINT managed_space_members_did_check CHECK (chat.is_bare_did(member_did))
);

CREATE TABLE IF NOT EXISTS chat.conversation_space_records (
    space_uri TEXT NOT NULL REFERENCES chat.conversation_spaces(space_uri) ON DELETE CASCADE,
    writer_did TEXT NOT NULL,
    collection TEXT NOT NULL,
    rkey TEXT NOT NULL,
    cid TEXT NOT NULL,
    record_cbor BYTEA NOT NULL CHECK (octet_length(record_cbor) BETWEEN 1 AND 1048576),
    repo_rev TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (space_uri, writer_did, collection, rkey),
    CONSTRAINT conversation_space_records_did_check CHECK (chat.is_bare_did(writer_did))
);

CREATE INDEX IF NOT EXISTS conversation_space_records_repo_idx
    ON chat.conversation_space_records (space_uri, writer_did, collection ASC, rkey ASC);
