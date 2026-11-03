-- 20261104000011_direct_request_route_answers.sql
-- Mark the pair coordinator's answer on a sender home's outbound route, and
-- until when a route no coordinator answered binds its pair.
--
-- A sender home records its route before relaying `prepareDirectRequest` to a
-- remote pair coordinator. `answered_at` is set once that coordinator answers,
-- or the relay fails for a reason no retry cures, and by `publishDirectRequest`,
-- which records its route only after an answer. An answered route binds its
-- pair permanently, as every route did before: its `binding_expires_at` is
-- NULL. An unanswered route, left when identical prepares all failed
-- transiently, binds its pair only until `binding_expires_at`: the latest
-- instant a preparation made from the authenticated signed prepare could still
-- be live (`signedAt` plus the 300-second admission window plus the 300-second
-- preparation lease). It is set when the route is recorded; an identical retry
-- never changes it. The expiry sweeper deletes an unanswered route an hour
-- after it was recorded, once the hourly route quota no longer counts it.
-- Before this migration routes recorded no answer and bound their pairs
-- permanently, so existing routes are marked answered and keep binding.

ALTER TABLE chat.direct_request_outbound_routes
    ADD COLUMN answered_at TIMESTAMPTZ,
    ADD COLUMN binding_expires_at TIMESTAMPTZ;

UPDATE chat.direct_request_outbound_routes SET answered_at = created_at;

ALTER TABLE chat.direct_request_outbound_routes
    ADD CONSTRAINT direct_request_outbound_routes_binding_check
    CHECK ((answered_at IS NULL) = (binding_expires_at IS NOT NULL));

CREATE INDEX direct_request_outbound_routes_unanswered
    ON chat.direct_request_outbound_routes (created_at, request_id)
    WHERE answered_at IS NULL;
