-- Match the strict generated submitTransition representation adapter without
-- modifying any applied migration or operation-claim authority constraint.
-- Only the five canonical outer tags can supply a missing singleton body tag.
-- Legacy body-tag requirements and the duplicate-preserving, NUL-safe JSON
-- extraction remain unchanged. Full schema/signature validation stays in Rust;
-- the deferred mapping still independently checks wrapper/transcript/claim
-- kinds, endpoint, digest, signature and the hash of exact submitted bytes.
-- CREATE OR REPLACE is intentionally safe to reapply on an upgraded database.

CREATE OR REPLACE FUNCTION chat.exact_wrapper_body_type(wrapper BYTEA)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    sanitized BYTEA := wrapper;
    cursor INTEGER := 0;
    length INTEGER := octet_length(wrapper);
    slash_start INTEGER;
    slash_count INTEGER;
    document JSON;
    body_value JSON;
    type_value JSON;
    body_count BIGINT;
    type_count BIGINT;
    outer_type_value JSON;
    outer_type_count BIGINT;
    root_field_count BIGINT;
    signature_count BIGINT;
    expected_type TEXT;
BEGIN
    WHILE cursor < length LOOP
        IF get_byte(wrapper,cursor) <> 92 THEN
            cursor := cursor + 1;
            CONTINUE;
        END IF;
        slash_start := cursor;
        WHILE cursor < length
          AND get_byte(wrapper,cursor) = 92 LOOP
            cursor := cursor + 1;
        END LOOP;
        slash_count := cursor - slash_start;
        IF (slash_count % 2) = 1
           AND cursor + 4 < length
           AND get_byte(wrapper,cursor) = 117
           AND get_byte(wrapper,cursor + 1) = 48
           AND get_byte(wrapper,cursor + 2) = 48
           AND get_byte(wrapper,cursor + 3) = 48
           AND get_byte(wrapper,cursor + 4) = 48 THEN
            sanitized := set_byte(sanitized,cursor + 4,49);
        END IF;
    END LOOP;

    document := convert_from(sanitized,'UTF8')::json;
    SELECT count(*), min(value::text)::json
      INTO body_count, body_value
      FROM json_each(document)
     WHERE key = 'body';
    IF body_count <> 1 OR json_typeof(body_value) <> 'object' THEN
        RETURN NULL;
    END IF;

    SELECT count(*), min(value::text)::json
      INTO type_count, type_value
      FROM json_each(body_value)
     WHERE key = '$type';
    SELECT count(*), min(value::text)::json
      INTO outer_type_count, outer_type_value
      FROM json_each(document)
     WHERE key = '$type';

    IF outer_type_count = 0 THEN
        -- Native/legacy wrappers still require one explicit body discriminator.
        IF type_count <> 1 OR json_typeof(type_value) <> 'string' THEN
            RETURN NULL;
        END IF;
        RETURN type_value #>> '{}';
    END IF;

    IF outer_type_count <> 1 OR json_typeof(outer_type_value) <> 'string' THEN
        RETURN NULL;
    END IF;
    SELECT count(*), count(*) FILTER (WHERE key = 'signature')
      INTO root_field_count, signature_count
      FROM json_each(document);
    IF root_field_count <> 3 OR signature_count <> 1 THEN
        RETURN NULL;
    END IF;

    expected_type := CASE outer_type_value #>> '{}'
        WHEN 'blue.catbird.chat.defs#signedCommitTransition' THEN 'blue.catbird.chat.defs#commitTransitionBody'
        WHEN 'blue.catbird.chat.defs#signedPolicyTransition' THEN 'blue.catbird.chat.defs#policyTransitionBody'
        WHEN 'blue.catbird.chat.defs#signedLeafRecoveryFulfillment' THEN 'blue.catbird.chat.defs#leafRecoveryFulfillmentBody'
        WHEN 'blue.catbird.chat.defs#signedMetadataTransition' THEN 'blue.catbird.chat.defs#metadataTransitionBody'
        WHEN 'blue.catbird.chat.defs#signedLeaveCommitFulfillment' THEN 'blue.catbird.chat.defs#leaveCommitFulfillmentBody'
        ELSE NULL
    END;
    IF expected_type IS NULL THEN
        RETURN NULL;
    END IF;

    -- Generated Rust singleton-union bodies omit $type. An explicitly supplied
    -- tag, including null or duplicate decoded keys, must still match exactly.
    IF type_count = 0 THEN
        RETURN expected_type;
    END IF;
    IF type_count <> 1
       OR json_typeof(type_value) <> 'string'
       OR (type_value #>> '{}') <> expected_type THEN
        RETURN NULL;
    END IF;
    RETURN expected_type;
EXCEPTION
    WHEN OTHERS THEN
        RETURN NULL;
END
$$;
