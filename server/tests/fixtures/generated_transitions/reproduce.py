#!/usr/bin/env python3
"""Produce/check actual generated Swift DTO bytes without changing either SDK."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
WORKSPACE = HERE.parents[4]
PACKAGE = HERE / "SwiftProducer"
PINS = {
    "Petrel": "e115236537041a900ec971be05185a70cca73e8a",
    "PetrelCatbird": "8672c80ffeb3b9cfbdb6bd98f66efa09b13fe0db",
}
SOURCE_FILES = (
    "mls-ds/server/tests/fixtures/mls_chat_control_fingerprint_source.json",
    "mls-ds/server/tests/fixtures/mls_chat_contract_vectors.json",
    "mls-ds/lexicon/blue/catbird/chat/blue.catbird.chat.defs.json",
    "PetrelCatbird/lexicons/blue/catbird/chat/blue.catbird.chat.defs.json",
    "PetrelCatbird/lexicons/blue/catbird/chat/blue.catbird.chat.submitTransition.json",
    "PetrelCatbird/Sources/PetrelCatbird/Generated/Lexicons/Blue/Catbird/BlueCatbirdChatDefs.swift",
    "PetrelCatbird/Sources/PetrelCatbird/Generated/Lexicons/Blue/Catbird/BlueCatbirdChatSubmitTransition.swift",
    "Petrel/Sources/Petrel/Core/Utils/ATProtoTypes.swift",
)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(*args, cwd=HERE, capture=True):
    result = subprocess.run(args, cwd=cwd, text=True, capture_output=capture)
    if result.returncode:
        raise RuntimeError(f"Command failed ({' '.join(args)}):\n{result.stdout or ''}{result.stderr or ''}")
    return result.stdout


def verify_sources():
    for name, revision in PINS.items():
        root = WORKSPACE / name
        # Git is used only for object inspection and comparison, never mutation.
        run("git", "cat-file", "-e", revision + "^{commit}", cwd=root)
        run("git", "diff", "--exit-code", revision, "--", "Sources", "Package.swift", "lexicons", cwd=root)
        untracked = run("git", "ls-files", "--others", "--exclude-standard", "--", "Sources", "lexicons", cwd=root)
        if untracked.strip():
            raise RuntimeError(f"Unpinned source files in {name}: {untracked}")
    return {name: sha256(WORKSPACE / name) for name in SOURCE_FILES}


def verify_dependency_graph():
    graph = json.loads(run("swift", "package", "--package-path", str(PACKAGE), "show-dependencies", "--format", "json"))
    def nodes(node):
        yield node
        for dependency in node.get("dependencies", []):
            yield from nodes(dependency)
    records = {}
    for name in PINS:
        matches = [node for node in nodes(graph) if node.get("identity") == name.lower()]
        expected = (WORKSPACE / name).resolve()
        if not matches or any(Path(node.get("path", "")).resolve() != expected
                              or Path(node.get("url", "")).resolve() != expected for node in matches):
            raise RuntimeError(f"SwiftPM did not resolve every {name} edge to the verified local SDK")
        records[name] = {"kind": "local", "workspaceRelativePath": name, "edges": len(matches)}
    return records


def provenance(source_files, output, dependencies):
    producer_paths = [Path("SwiftProducer/Package.swift"), Path("reproduce.py")] + [
        path.relative_to(HERE) for path in sorted((PACKAGE / "Sources").rglob("*.swift"))
    ]
    if (PACKAGE / "Package.resolved").is_file():
        producer_paths.append(Path("SwiftProducer/Package.resolved"))
    inputs = sorted((HERE / "inputs").glob("*.json"))
    return {
        "schemaVersion": 1,
        "purpose": "Actual generated Swift serializer fixtures; signing values copied from independent server vectors",
        "qualification": "DTO encoding and typed roundtrip only; production decoder, crypto, handler, DB and MLS validity are tested separately",
        "sourceRevisions": PINS,
        "resolvedSDKs": dependencies,
        "swiftToolchain": run("swift", "--version").strip(),
        "sourceFilesSHA256": source_files,
        "producerFilesSHA256": {str(path): sha256(HERE / path) for path in producer_paths},
        "supplementalInputsSHA256": {str(path.relative_to(HERE)): sha256(path) for path in inputs},
        "outputFilesSHA256": {path.name: sha256(path) for path in sorted(output.glob("*.json"))},
        "reproduceCommand": "python3 server/tests/fixtures/generated_transitions/reproduce.py --check",
        "regenerateCommand": "python3 server/tests/fixtures/generated_transitions/reproduce.py --write",
        "producer": "SwiftProducer/Sources/GeneratedTransitionProducer/main.swift",
        "encoding": "JSONEncoder.encode(actual generated Input), sortedKeys and withoutEscapingSlashes; no post-encoding JSON rewrite",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="default: regenerate to temporary storage and compare exact bytes")
    mode.add_argument("--write", action="store_true", help="write new generated fixtures, preserving replaced files")
    mode.add_argument("--decode-response", nargs=2, metavar=("KIND", "JSON_FILE"))
    mode.add_argument("--encode-wrapper", nargs=3, metavar=("VARIANT", "JSON_FILE", "OUTPUT_DIR"))
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    source_files = verify_sources()
    run("swift", "build", "--package-path", str(PACKAGE), "--jobs", str(args.jobs), capture=False)
    dependencies = verify_dependency_graph()
    bin_dir = run("swift", "build", "--package-path", str(PACKAGE), "--show-bin-path").strip()
    executable = str(Path(bin_dir) / "GeneratedTransitionProducer")
    if args.decode_response:
        kind, response = args.decode_response
        run(executable, "decode-response", kind, str(Path(response).resolve()), capture=False)
        return
    if args.encode_wrapper:
        variant, wrapper, output = args.encode_wrapper
        run(executable, "encode-wrapper", str(WORKSPACE), variant,
            str(Path(wrapper).resolve()), str(Path(output).resolve()), capture=False)
        if verify_sources() != source_files:
            raise RuntimeError("Source inputs changed while encoding wrapper")
        return
    with tempfile.TemporaryDirectory(prefix="generated-swift-transitions-") as directory:
        output = Path(directory)
        run(executable, "generate", str(WORKSPACE), str(output), capture=False)
        if verify_sources() != source_files:
            raise RuntimeError("Source inputs changed while producing fixtures")
        record = provenance(source_files, output, dependencies)
        (output / "provenance.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        produced = sorted(output.glob("*.json"))
        changed = [path for path in produced
                   if not (HERE / path.name).is_file() or path.read_bytes() != (HERE / path.name).read_bytes()]
        if args.write:
            retained = HERE / "_trash" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
            for path in changed:
                existing = HERE / path.name
                if existing.exists():
                    retained.mkdir(parents=True, exist_ok=True)
                    shutil.move(existing, retained / existing.name)
                shutil.copyfile(path, existing)
            print(f"Wrote {len(changed)} generated files; SDK sources and original frozen vectors unchanged")
        elif changed:
            raise RuntimeError("Generated fixture bytes differ: " + ", ".join(path.name for path in changed))
        else:
            print(f"Verified {len(produced)} exact generated fixture/provenance files")


if __name__ == "__main__":
    main()
