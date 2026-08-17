-- Enable durable operation claims for the clean sendMessage procedure.
-- publishTyping is intentionally absent: it is ephemeral and is coalesced in
-- runtime state after authorization, so it must not create durable claims.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
        WHERE conrelid='chat.operation_claims'::regclass
          AND conname='operation_claims_endpoint_check')
       OR NOT EXISTS (SELECT 1 FROM pg_constraint
        WHERE conrelid='chat.idempotency_records'::regclass
          AND conname='idempotency_records_endpoint_check') THEN
        RAISE EXCEPTION 'chat claim constraints missing; refusing unsafe forward migration';
    END IF;
END $$;

ALTER TABLE chat.operation_claims
    DROP CONSTRAINT IF EXISTS operation_claims_endpoint_check;

ALTER TABLE chat.operation_claims
    ADD CONSTRAINT operation_claims_endpoint_check CHECK (
        endpoint_nsid = ANY (ARRAY[
            'blue.catbird.chat.acceptConversation',
            'blue.catbird.chat.acknowledgeWelcome',
            'blue.catbird.chat.activateReset',
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
    DROP CONSTRAINT IF EXISTS idempotency_records_endpoint_check;

ALTER TABLE chat.idempotency_records
    ADD CONSTRAINT idempotency_records_endpoint_check CHECK (
        endpoint_nsid = ANY (ARRAY[
            'blue.catbird.chat.acceptConversation',
            'blue.catbird.chat.acknowledgeWelcome',
            'blue.catbird.chat.activateReset',
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
