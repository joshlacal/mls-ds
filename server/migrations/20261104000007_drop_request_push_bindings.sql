-- `updatePushToken`'s signed token-hash bindings. Direct-request wakes use
-- `chat.push_gateway_bindings` (D2): nothing writes or reads this table, and its
-- guard refused device revocation's DELETE of any row it held.
DROP TABLE chat.request_push_bindings;
DROP FUNCTION chat.guard_request_push_binding();
