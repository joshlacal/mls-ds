-- Correct migration13's JSON iteration: PostgreSQL JSON accessors also decode NUL.
-- Encode all string NUL codepoints as SOH followed by literal 0, and all existing
-- SOH codepoints as SOH followed by literal 1, before accessing JSON structure.
-- This prefix code is injective over Unicode strings, including object keys.
-- Escape atoms are consumed whole: a literal backslash followed by u0000 is not
-- a NUL escape. JSON permits neither control codepoint unescaped, so there is no
-- alternate literal spelling to miss. Other escapes retain PostgreSQL semantics.
-- This affects only transient equality projections, never signed/stored bytes.
-- Keep migration13's duplicate-key, signature-domain-type and nesting fences.
CREATE FUNCTION chat.direct_request_json_structure(document JSON, depth INTEGER DEFAULT 0)
RETURNS JSONB LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE projected JSONB;
        field RECORD;
        element JSON;
BEGIN
    IF depth > 64 THEN
        RAISE EXCEPTION 'request JSON nesting exceeds comparison limit' USING ERRCODE='23514';
    END IF;
    CASE json_typeof(document)
    WHEN 'object' THEN
        projected := '{}'::jsonb;
        FOR field IN SELECT key, value FROM json_each(document) LOOP
            IF projected ? field.key THEN
                RAISE EXCEPTION 'duplicate request JSON field' USING ERRCODE='23514';
            END IF;
            IF field.key = 'signatureDomain' THEN
                IF json_typeof(field.value) <> 'string' THEN
                    RAISE EXCEPTION 'request signature domain must be a string' USING ERRCODE='23514';
                END IF;
                projected := projected || jsonb_build_object(field.key, field.value::jsonb);
            ELSE
                projected := projected || jsonb_build_object(field.key,
                    chat.direct_request_json_structure(field.value, depth + 1));
            END IF;
        END LOOP;
        RETURN projected;
    WHEN 'array' THEN
        projected := '[]'::jsonb;
        FOR element IN SELECT value FROM json_array_elements(document) LOOP
            projected := projected || jsonb_build_array(
                chat.direct_request_json_structure(element, depth + 1));
        END LOOP;
        RETURN projected;
    ELSE
        RETURN document::jsonb;
    END CASE;
END $$;

CREATE OR REPLACE FUNCTION chat.direct_request_json_projection(document JSON, depth INTEGER DEFAULT 0)
RETURNS JSONB LANGUAGE sql IMMUTABLE STRICT AS $function$
    SELECT chat.direct_request_json_structure(
        string_agg(CASE token[1]
            WHEN $atom$\u0000$atom$ THEN $atom$\u00010$atom$
            WHEN $atom$\u0001$atom$ THEN $atom$\u00011$atom$
            ELSE token[1] END, '' ORDER BY ordinal)::json,
        depth)
    FROM regexp_matches(document::text, $regex$\\u000[01]|\\.|[^\\]+$regex$, 'g')
        WITH ORDINALITY AS escaped(token, ordinal)
$function$;
