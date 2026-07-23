#!/usr/bin/env python3
"""Deterministically regenerate the frozen control-entry fingerprint corpus.

The semantic inputs live in ``fixtures/mls_chat_control_fingerprint_source.json``.
That source contains readable tagged bytes/UUIDs plus test-only Ed25519 seeds; it
does not contain any derived CBOR, transcript, digest, signature, or fingerprint.
This script derives those fields and replaces only the generated control section
of ``mls_chat_contract_vectors.json``, preserving the unrelated golden vectors.
"""

from __future__ import annotations

import argparse
import base64
import copy
import difflib
import hashlib
import json
import os
import tempfile
import uuid
from pathlib import Path
from typing import Any


SAFE_INTEGER_MAX = 9_007_199_254_740_991
TESTS_ROOT = Path(__file__).resolve().parent
MLS_DS_ROOT = TESTS_ROOT.parents[1]
STACK_ROOT = MLS_DS_ROOT.parent
SOURCE_PATH = TESTS_ROOT / "fixtures/mls_chat_control_fingerprint_source.json"
TARGET_PATH = TESTS_ROOT / "fixtures/mls_chat_contract_vectors.json"
GENERATOR_RELATIVE_PATH = "mls-ds/server/tests/generate_mls_chat_contract_vectors.py"
SOURCE_RELATIVE_PATH = (
    "mls-ds/server/tests/fixtures/mls_chat_control_fingerprint_source.json"
)
TARGET_RELATIVE_PATH = "mls-ds/server/tests/fixtures/mls_chat_contract_vectors.json"
WRITE_COMMAND = f"python3 {GENERATOR_RELATIVE_PATH} --write"
CHECK_COMMAND = f"python3 {GENERATOR_RELATIVE_PATH} --check"

CONTROL_ENTRY_CASES = (
    (
        "blue.catbird.chat.defs#commitEntry",
        "blue.catbird.chat.defs#signedCommitTransition",
        "blue.catbird.chat.defs#commitTransitionBody",
        "CATBIRD-CHAT-COMMIT\0",
    ),
    (
        "blue.catbird.chat.defs#policyEntry",
        "blue.catbird.chat.defs#signedPolicyTransition",
        "blue.catbird.chat.defs#policyTransitionBody",
        "CATBIRD-CHAT-POLICY\0",
    ),
    (
        "blue.catbird.chat.defs#metadataEntry",
        "blue.catbird.chat.defs#signedMetadataTransition",
        "blue.catbird.chat.defs#metadataTransitionBody",
        "CATBIRD-CHAT-METADATA\0",
    ),
    (
        "blue.catbird.chat.defs#creationEntry",
        "blue.catbird.chat.defs#signedCreation",
        "blue.catbird.chat.defs#creationBody",
        "CATBIRD-CHAT-CREATE\0",
    ),
    (
        "blue.catbird.chat.defs#participantAcceptanceEntry",
        "blue.catbird.chat.defs#signedParticipantAcceptance",
        "blue.catbird.chat.defs#participantAcceptanceBody",
        "CATBIRD-CHAT-ACCEPT\0",
    ),
    (
        "blue.catbird.chat.defs#conversationCloseEntry",
        "blue.catbird.chat.defs#signedConversationClose",
        "blue.catbird.chat.defs#conversationCloseBody",
        "CATBIRD-CHAT-CLOSE\0",
    ),
    (
        "blue.catbird.chat.defs#resetRequestEntry",
        "blue.catbird.chat.defs#signedResetRequest",
        "blue.catbird.chat.defs#resetRequestBody",
        "CATBIRD-CHAT-RESET-REQUEST\0",
    ),
    (
        "blue.catbird.chat.defs#resetActivationEntry",
        "blue.catbird.chat.defs#signedResetActivation",
        "blue.catbird.chat.defs#resetActivationBody",
        "CATBIRD-CHAT-RESET-ACTIVATE\0",
    ),
    (
        "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry",
        "blue.catbird.chat.defs#signedLeafRecoveryFulfillment",
        "blue.catbird.chat.defs#leafRecoveryFulfillmentBody",
        "CATBIRD-CHAT-LEAF-RECOVERY-FULFILL\0",
    ),
    (
        "blue.catbird.chat.defs#leaveRequestEntry",
        "blue.catbird.chat.defs#signedLeaveRequest",
        "blue.catbird.chat.defs#leaveRequestBody",
        "CATBIRD-CHAT-LEAVE-REQUEST\0",
    ),
    (
        "blue.catbird.chat.defs#zeroLeafLeaveEntry",
        "blue.catbird.chat.defs#signedZeroLeafLeave",
        "blue.catbird.chat.defs#zeroLeafLeaveBody",
        "CATBIRD-CHAT-LEAVE-ZERO-LEAF\0",
    ),
    (
        "blue.catbird.chat.defs#leaveCancellationEntry",
        "blue.catbird.chat.defs#signedLeaveCancellation",
        "blue.catbird.chat.defs#leaveCancellationBody",
        "CATBIRD-CHAT-LEAVE-CANCEL\0",
    ),
    (
        "blue.catbird.chat.defs#leaveCommitFulfillmentEntry",
        "blue.catbird.chat.defs#signedLeaveCommitFulfillment",
        "blue.catbird.chat.defs#leaveCommitFulfillmentBody",
        "CATBIRD-CHAT-LEAVE-FULFILL-COMMIT\0",
    ),
)


def strict_json_load_bytes(source: bytes, path: Path) -> Any:
    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result

    return json.loads(
        source.decode("utf-8"),
        object_pairs_hook=reject_duplicate,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON number {value!r} in {path}")
        ),
    )


def strict_json_load(path: Path) -> Any:
    return strict_json_load_bytes(path.read_bytes(), path)


def encode_major(major: int, length: int) -> bytes:
    if not (0 <= major <= 7 and 0 <= length <= SAFE_INTEGER_MAX):
        raise ValueError("DAG-CBOR major/length is outside the frozen profile")
    prefix = major << 5
    if length < 24:
        return bytes([prefix | length])
    if length <= 0xFF:
        return bytes([prefix | 24, length])
    if length <= 0xFFFF:
        return bytes([prefix | 25]) + length.to_bytes(2, "big")
    if length <= 0xFFFFFFFF:
        return bytes([prefix | 26]) + length.to_bytes(4, "big")
    return bytes([prefix | 27]) + length.to_bytes(8, "big")


def encode_dag_cbor(value: Any) -> bytes:
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if type(value) is int and 0 <= value <= SAFE_INTEGER_MAX:
        return encode_major(0, value)
    if isinstance(value, bytes):
        return encode_major(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return encode_major(3, len(encoded)) + encoded
    if isinstance(value, list):
        return encode_major(4, len(value)) + b"".join(
            encode_dag_cbor(item) for item in value
        )
    if isinstance(value, dict):
        items: list[tuple[int, bytes, bytes]] = []
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("DAG-CBOR map keys must be text")
            encoded_key = encode_dag_cbor(key)
            items.append((len(encoded_key), encoded_key, encode_dag_cbor(item)))
        items.sort(key=lambda item: (item[0], item[1]))
        return encode_major(5, len(items)) + b"".join(
            key + item for _, key, item in items
        )
    raise ValueError(f"unsupported DAG-CBOR source value {value!r}")


_ED25519_P = 2**255 - 19
_ED25519_Q = 2**252 + 27742317777372353535851937790883648493
_ED25519_D = (-121665 * pow(121666, _ED25519_P - 2, _ED25519_P)) % _ED25519_P
_ED25519_I = pow(2, (_ED25519_P - 1) // 4, _ED25519_P)


def ed25519_recover_x(y: int, sign: int) -> int:
    if y >= _ED25519_P:
        raise ValueError("non-canonical Ed25519 y-coordinate")
    xx = (
        (y * y - 1)
        * pow(_ED25519_D * y * y + 1, _ED25519_P - 2, _ED25519_P)
    ) % _ED25519_P
    x = pow(xx, (_ED25519_P + 3) // 8, _ED25519_P)
    if (x * x - xx) % _ED25519_P:
        x = (x * _ED25519_I) % _ED25519_P
    if (x * x - xx) % _ED25519_P:
        raise ValueError("invalid Ed25519 point")
    return _ED25519_P - x if (x & 1) != sign else x


def ed25519_encode_point(point: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = point
    inverse_z = pow(z, _ED25519_P - 2, _ED25519_P)
    affine_x = (x * inverse_z) % _ED25519_P
    affine_y = (y * inverse_z) % _ED25519_P
    return (affine_y | ((affine_x & 1) << 255)).to_bytes(32, "little")


def ed25519_add(
    left: tuple[int, int, int, int], right: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = ((y1 - x1) * (y2 - x2)) % _ED25519_P
    b = ((y1 + x1) * (y2 + x2)) % _ED25519_P
    c = (2 * _ED25519_D * t1 * t2) % _ED25519_P
    d = (2 * z1 * z2) % _ED25519_P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (
        e * f % _ED25519_P,
        g * h % _ED25519_P,
        f * g % _ED25519_P,
        e * h % _ED25519_P,
    )


def ed25519_multiply(
    scalar: int, point: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    result = (0, 1, 1, 0)
    while scalar:
        if scalar & 1:
            result = ed25519_add(result, point)
        point = ed25519_add(point, point)
        scalar >>= 1
    return result


_ED25519_BASE_Y = (4 * pow(5, _ED25519_P - 2, _ED25519_P)) % _ED25519_P
_ED25519_BASE_X = ed25519_recover_x(_ED25519_BASE_Y, 0)
_ED25519_BASE = (
    _ED25519_BASE_X,
    _ED25519_BASE_Y,
    1,
    (_ED25519_BASE_X * _ED25519_BASE_Y) % _ED25519_P,
)


def ed25519_secret_scalar(seed: bytes) -> tuple[int, bytes]:
    if len(seed) != 32:
        raise ValueError("test-only Ed25519 seed must be exactly 32 bytes")
    expanded = hashlib.sha512(seed).digest()
    scalar_bytes = bytearray(expanded[:32])
    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 63
    scalar_bytes[31] |= 64
    return int.from_bytes(scalar_bytes, "little"), expanded[32:]


def ed25519_public_key(seed: bytes) -> bytes:
    scalar, _ = ed25519_secret_scalar(seed)
    return ed25519_encode_point(ed25519_multiply(scalar, _ED25519_BASE))


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    scalar, prefix = ed25519_secret_scalar(seed)
    public_key = ed25519_public_key(seed)
    nonce = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _ED25519_Q
    encoded_nonce = ed25519_encode_point(ed25519_multiply(nonce, _ED25519_BASE))
    challenge = int.from_bytes(
        hashlib.sha512(encoded_nonce + public_key + message).digest(), "little"
    ) % _ED25519_Q
    signature_scalar = (nonce + challenge * scalar) % _ED25519_Q
    return encoded_nonce + signature_scalar.to_bytes(32, "little")


def key_id(public_key: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(public_key).digest()).decode(
        "ascii"
    ).rstrip("=")


def canonical_key_id(value: str) -> bool:
    if len(value) != 43 or not all(
        character.isascii() and (character.isalnum() or character in "-_")
        for character in value
    ):
        return False
    try:
        decoded = base64.b64decode(value + "=", altchars=b"-_", validate=True)
    except ValueError:
        return False
    return (
        len(decoded) == 32
        and base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") == value
    )


def decode_source_value(value: Any, path: str = "body") -> Any:
    if isinstance(value, dict):
        if set(value) == {"$bytesHex"}:
            encoded = value["$bytesHex"]
            if not isinstance(encoded, str) or encoded != encoded.lower():
                raise ValueError(f"{path} has a non-canonical $bytesHex marker")
            decoded = bytes.fromhex(encoded)
            if decoded.hex() != encoded:
                raise ValueError(f"{path} has a non-canonical $bytesHex marker")
            return decoded
        if set(value) == {"$uuid"}:
            encoded = value["$uuid"]
            identifier = uuid.UUID(encoded)
            if (
                str(identifier) != encoded
                or identifier.version != 4
                or identifier.variant != uuid.RFC_4122
            ):
                raise ValueError(f"{path} has a non-canonical UUIDv4 marker")
            return identifier.bytes
        if "$bytesHex" in value or "$uuid" in value:
            raise ValueError(f"{path} mixes a source marker with semantic fields")
        return {
            key: decode_source_value(child, f"{path}.{key}")
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [
            decode_source_value(child, f"{path}[{index}]")
            for index, child in enumerate(value)
        ]
    if value is None or isinstance(value, float) or (type(value) is int and value < 0):
        raise ValueError(f"{path} contains a value outside the frozen DAG-CBOR profile")
    return value


def collect_key_binding_issues(value: Any, path: str = "body") -> list[str]:
    issues: list[str] = []
    if isinstance(value, dict):
        for field in ("keyId", "authorKeyId", "requesterKeyId"):
            candidate = value.get(field)
            if candidate is not None and (
                not isinstance(candidate, str) or not canonical_key_id(candidate)
            ):
                issues.append(f"{path}.{field} is not canonical base64url SHA-256")
            public_key = value.get("signaturePublicKey")
            if isinstance(candidate, str) and isinstance(public_key, bytes):
                if candidate != key_id(public_key):
                    issues.append(
                        f"{path}.{field} does not bind {path}.signaturePublicKey"
                    )
        for field, child in value.items():
            issues.extend(collect_key_binding_issues(child, f"{path}.{field}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            issues.extend(collect_key_binding_issues(child, f"{path}[{index}]"))
    return issues


def source_at_path(value: Any, path: str) -> Any:
    current = value
    for part in path.split("."):
        current = current[int(part)] if isinstance(current, list) else current[part]
    return current


def set_at_path(value: Any, path: str, replacement: Any) -> None:
    current = value
    parts = path.split(".")
    for part in parts[:-1]:
        current = current[int(part)] if isinstance(current, list) else current[part]
    final = parts[-1]
    if isinstance(current, list):
        current[int(final)] = replacement
    else:
        current[final] = replacement


def outer_projection(
    value: dict[str, Any], uuid_paths: list[str], base64_paths: list[str]
) -> dict[str, Any]:
    projection = copy.deepcopy(value)
    for path in uuid_paths:
        encoded = source_at_path(projection, path)
        if not isinstance(encoded, str):
            raise ValueError(f"outer UUID path {path} is not text")
        identifier = uuid.UUID(encoded)
        if (
            str(identifier) != encoded
            or identifier.version != 4
            or identifier.variant != uuid.RFC_4122
        ):
            raise ValueError(f"outer UUID path {path} is not canonical UUIDv4")
        set_at_path(projection, path, identifier.bytes)
    for path in base64_paths:
        encoded = source_at_path(projection, path)
        if not isinstance(encoded, str):
            raise ValueError(f"outer base64 path {path} is not text")
        decoded = base64.b64decode(encoded, validate=True)
        if base64.b64encode(decoded).decode("ascii") != encoded:
            raise ValueError(f"outer base64 path {path} is not canonical")
        set_at_path(projection, path, decoded)
    return projection


def render_control_corpus(source: dict[str, Any]) -> dict[str, Any]:
    expected_source_keys = {
        "schemaVersion",
        "protocol",
        "protocolVersion",
        "purpose",
        "testOnlySigningSeedsHex",
        "domain",
        "projectionFields",
        "ordinaryServerFields",
        "nonemptyServerFields",
        "authoritativeReferenceBindings",
        "cases",
    }
    if set(source) != expected_source_keys:
        raise ValueError("control source top-level fields drifted")
    if (
        source["schemaVersion"] != 1
        or source["protocol"] != "blue.catbird.chat"
        or source["protocolVersion"] != "1"
    ):
        raise ValueError("control source protocol identity drifted")
    if source["projectionFields"] != [
        "entryKind",
        "entryId",
        "conversationId",
        "seq",
        "requestDigest",
        "signature",
        "serverFields",
        "receivedAt",
    ]:
        raise ValueError("control source projection field order drifted")

    seed_records = source["testOnlySigningSeedsHex"]
    if list(seed_records) != ["activeAdminDevice7272", "requesterDevice7070"]:
        raise ValueError("control source signing-key set/order drifted")
    seeds: dict[str, bytes] = {}
    public_keys: dict[str, bytes] = {}
    for name, encoded_seed in seed_records.items():
        seed = bytes.fromhex(encoded_seed)
        if len(seed) != 32 or seed.hex() != encoded_seed:
            raise ValueError(f"test-only signing seed {name} is not canonical")
        seeds[name] = seed
        public_keys[name] = ed25519_public_key(seed)

    cases = source["cases"]
    if not isinstance(cases, list) or len(cases) != len(CONTROL_ENTRY_CASES):
        raise ValueError("control source must contain exactly 13 cases")
    output_cases: list[dict[str, Any]] = []
    for source_case, expected in zip(cases, CONTROL_ENTRY_CASES):
        expected_case_keys = {
            "entryKind",
            "signedRequestRef",
            "signingDomain",
            "historicalPublicKeyRef",
            "entryId",
            "conversationId",
            "seq",
            "serverFields",
            "receivedAt",
            "uuidBytePaths",
            "base64BytePaths",
            "body",
        }
        if set(source_case) != expected_case_keys:
            raise ValueError("control source case fields drifted")
        entry_kind, signed_ref, body_type, signing_domain = expected
        if (
            source_case["entryKind"],
            source_case["signedRequestRef"],
            source_case["signingDomain"],
        ) != (entry_kind, signed_ref, signing_domain):
            raise ValueError(f"control source identity drifted for {entry_kind}")
        body = decode_source_value(source_case["body"])
        if body.get("$type") != body_type or body.get("signatureDomain") != signing_domain:
            raise ValueError(f"signed body identity drifted for {entry_kind}")
        if entry_kind == "blue.catbird.chat.defs#creationEntry" and body.get(
            "absence"
        ) is not True:
            raise ValueError("creationBody.absence must be the frozen constant true")
        key_ref = source_case["historicalPublicKeyRef"]
        if key_ref not in seeds:
            raise ValueError(f"unknown historical signing key {key_ref!r}")
        expected_signer_key_id = key_id(public_keys[key_ref])
        if body.get("keyId") != expected_signer_key_id:
            raise ValueError(f"body.keyId does not bind {key_ref} for {entry_kind}")
        key_issues = collect_key_binding_issues(body)
        if key_issues:
            raise ValueError(f"{entry_kind}: " + "; ".join(key_issues))

        unsigned_projection = encode_dag_cbor(body)
        transcript = signing_domain.encode("utf-8") + unsigned_projection
        request_digest = hashlib.sha256(transcript).digest()
        signature = ed25519_sign(seeds[key_ref], transcript)
        request_digest_base64 = base64.b64encode(request_digest).decode("ascii")
        signature_base64 = base64.b64encode(signature).decode("ascii")
        fingerprint_input = {
            "entryKind": entry_kind,
            "entryId": source_case["entryId"],
            "conversationId": source_case["conversationId"],
            "seq": source_case["seq"],
            "requestDigest": request_digest_base64,
            "signature": signature_base64,
            "serverFields": source_case["serverFields"],
            "receivedAt": source_case["receivedAt"],
        }
        canonical_outer = encode_dag_cbor(
            outer_projection(
                fingerprint_input,
                source_case["uuidBytePaths"],
                source_case["base64BytePaths"],
            )
        )
        fingerprint = hashlib.sha256(
            source["domain"].encode("utf-8") + canonical_outer
        ).hexdigest()
        output_cases.append(
            {
                "entryKind": entry_kind,
                "signedRequestRef": signed_ref,
                "signingDomain": signing_domain,
                "unsignedSigningProjectionCanonicalDagCborHex": unsigned_projection.hex(),
                "signingTranscriptHex": transcript.hex(),
                "historicalPublicKeyRef": key_ref,
                "entryId": source_case["entryId"],
                "conversationId": source_case["conversationId"],
                "seq": source_case["seq"],
                "requestDigest": request_digest_base64,
                "signature": signature_base64,
                "serverFields": source_case["serverFields"],
                "receivedAt": source_case["receivedAt"],
                "uuidBytePaths": source_case["uuidBytePaths"],
                "base64BytePaths": source_case["base64BytePaths"],
                "canonicalDagCborHex": canonical_outer.hex(),
                "fingerprintSha256Hex": fingerprint,
            }
        )

    return {
        "domain": source["domain"],
        "projectionFields": source["projectionFields"],
        "ordinaryServerFields": source["ordinaryServerFields"],
        "nonemptyServerFields": source["nonemptyServerFields"],
        "historicalPublicKeys": {
            name: public_key.hex() for name, public_key in public_keys.items()
        },
        "authoritativeReferenceBindings": source["authoritativeReferenceBindings"],
        "cases": output_cases,
    }


def generation_record(source_bytes: bytes) -> dict[str, Any]:
    generator_bytes = Path(__file__).read_bytes()
    return {
        "schemaVersion": 1,
        "command": WRITE_COMMAND,
        "checkCommand": CHECK_COMMAND,
        "generator": GENERATOR_RELATIVE_PATH,
        "generatorSha256Hex": hashlib.sha256(generator_bytes).hexdigest(),
        "semanticSource": SOURCE_RELATIVE_PATH,
        "semanticSourceSha256Hex": hashlib.sha256(source_bytes).hexdigest(),
        "target": TARGET_RELATIVE_PATH,
        "derivation": (
            "test-only Ed25519 seed -> public key/keyId; semantic tagged body -> "
            "canonical DAG-CBOR; domain transcript -> SHA-256 digest + Ed25519 signature; "
            "closed outer projection -> canonical DAG-CBOR + domain-separated SHA-256"
        ),
    }


def format_root_member(name: str, value: Any) -> str:
    serialized = json.dumps(value, ensure_ascii=False, indent=2)
    lines = serialized.splitlines()
    return f"  {json.dumps(name)}: {lines[0]}" + "".join(
        f"\n  {line}" for line in lines[1:]
    )


def render_target(target_text: str, source_bytes: bytes) -> str:
    source = strict_json_load_bytes(source_bytes, SOURCE_PATH)
    control = render_control_corpus(source)
    start_markers = (
        '  "controlEntryFingerprintGeneration": {',
        '  "controlEntryFingerprints": {',
    )
    starts = [target_text.find(marker) for marker in start_markers]
    starts = [offset for offset in starts if offset >= 0]
    if not starts:
        raise ValueError("target lacks the generated control corpus marker")
    start = min(starts)
    next_member = '\n  "applicationSemanticConstraints": {'
    end = target_text.find(next_member, start)
    if end < 0:
        raise ValueError("target lacks the post-control corpus marker")
    generated = (
        format_root_member(
            "controlEntryFingerprintGeneration", generation_record(source_bytes)
        )
        + ",\n"
        + format_root_member("controlEntryFingerprints", control)
        + ","
    )
    return target_text[:start] + generated + target_text[end:]


def write_atomically(path: Path, value: str) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="fail if generated output drifted")
    mode.add_argument("--write", action="store_true", help="rewrite the generated control corpus")
    arguments = parser.parse_args()

    source_bytes = SOURCE_PATH.read_bytes()
    target_text = TARGET_PATH.read_text(encoding="utf-8")
    expected = render_target(target_text, source_bytes)
    if arguments.check:
        if expected == target_text:
            print(f"control corpus is current: {hashlib.sha256(target_text.encode()).hexdigest()}")
            return 0
        diff = difflib.unified_diff(
            target_text.splitlines(),
            expected.splitlines(),
            fromfile=str(TARGET_PATH),
            tofile="deterministically generated control corpus",
            lineterm="",
            n=2,
        )
        print("\n".join(diff))
        return 1
    write_atomically(TARGET_PATH, expected)
    print(f"wrote {TARGET_PATH}: {hashlib.sha256(expected.encode()).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
