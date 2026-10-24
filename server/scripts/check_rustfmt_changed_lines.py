#!/usr/bin/env python3
"""Reject rustfmt differences on lines changed since a reviewed Git base.

The full cargo-fmt report remains a separate CI artifact. This PR-only ratchet
does not require rewriting unrelated baseline code, including frozen fixtures.
It uses the base snapshot to locate edited lines and never writes source files.
"""

import argparse
from collections import Counter
import difflib
import os
from pathlib import Path
import subprocess
import sys


# Reviewed server integration before conversation Spaces; this is a fixed debt
# bootstrap, never an input that a future invocation can advance.
KNOWN_FORMAT_BASELINE = "c402df68efe98962db4f16e3bcd3f218776bc49d"


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args])


def changed_spans(before: list[str], after: list[str]) -> list[tuple[int, int]]:
    return [
        (start, end)
        for tag, _, _, start, end in difflib.SequenceMatcher(
            a=before, b=after, autojunk=False
        ).get_opcodes()
        if tag != "equal"
    ]


def overlaps(left: tuple[int, int], right: tuple[int, int]) -> bool:
    # Zero-width spans represent inserted formatting or deleted source. Include
    # their exact boundary so deleting a required separator cannot evade checks.
    a, b = left
    c, d = right
    if a == b:
        return c <= a <= d
    if c == d:
        return a <= c <= b
    return a < d and c < b


def formatting_hunks(source: str, path: str, root: Path) -> list:
    formatted = subprocess.run(
        ["rustfmt", "--edition", "2021", "--config", "skip_children=true", "--emit", "stdout"],
        input=source, text=True, capture_output=True, check=False, cwd=root,
    )
    if formatted.returncode:
        raise ValueError(f"rustfmt could not parse {path}:\n{formatted.stderr}")
    original_lines = source.splitlines(keepends=True)
    formatted_lines = formatted.stdout.splitlines(keepends=True)
    return [
        ((start, end), (tuple(original_lines[start:end]), tuple(formatted_lines[new_start:new_end])))
        for tag, start, end, new_start, new_end in difflib.SequenceMatcher(
            a=original_lines, b=formatted_lines, autojunk=False
        ).get_opcodes()
        if tag != "equal"
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, help="Existing base commit or ref")
    args = parser.parse_args()
    root = Path(git("rev-parse", "--show-toplevel").decode().strip())
    os.chdir(root)
    base = git("rev-parse", "--verify", "--end-of-options", f"{args.base}^{{commit}}")
    requested_base = base.decode().strip()

    def ancestor(older: str, newer: str) -> bool:
        result = subprocess.run(["git", "merge-base", "--is-ancestor", older, newer])
        if result.returncode not in (0, 1):
            raise RuntimeError("cannot verify formatting-baseline ancestry")
        return result.returncode == 0

    if not ancestor(KNOWN_FORMAT_BASELINE, "HEAD"):
        parser.error("checkout does not descend from the fixed reviewed formatting baseline")
    if ancestor(KNOWN_FORMAT_BASELINE, requested_base):
        base = requested_base
    elif ancestor(requested_base, KNOWN_FORMAT_BASELINE):
        base = KNOWN_FORMAT_BASELINE
    else:
        parser.error("PR base diverges from the fixed formatting baseline; review is required")
    print(f"PR base: {requested_base}; fixed debt bootstrap: {KNOWN_FORMAT_BASELINE}.")
    names = git("diff", "--name-only", "--diff-filter=ACMR", "-z", base, "--", "*.rs")
    paths = [name.decode() for name in names.split(b"\0") if name]
    violations = []
    baseline_hunks = 0

    for path in paths:
        source = (root / path).read_bytes().decode()
        previous = subprocess.run(
            ["git", "show", f"{base}:{path}"], capture_output=True, check=False
        )
        if previous.returncode:
            # A new or renamed path must be entirely formatted.
            changed = [(0, len(source.splitlines(keepends=True)))]
            previous_source = ""
        else:
            previous_source = previous.stdout.decode()
            changed = changed_spans(previous_source.splitlines(keepends=True), source.splitlines(keepends=True))
        try:
            existing_debt = Counter(signature for _, signature in formatting_hunks(previous_source, f"{base}:{path}", root))
            differences = formatting_hunks(source, path, root)
        except ValueError as error:
            print(error, file=sys.stderr)
            return 2
        for span, signature in differences:
            # Context edits can make untouched lines require indentation or
            # wrapping changes. Allow only exact existing debt, with bounded
            # multiplicity, rather than exempting every untouched source line.
            if any(overlaps(span, changed_span) for changed_span in changed) or not existing_debt[signature]:
                violations.append(f"{path}:{span[0] + 1}")
            else:
                existing_debt[signature] -= 1
                baseline_hunks += 1

    print(f"Checked {len(paths)} changed Rust files against {base}.")
    print(f"Existing formatting hunks outside changed lines: {baseline_hunks}.")
    if violations:
        print("New formatting differences or edited lines need rustfmt:", file=sys.stderr)
        print("\n".join(violations), file=sys.stderr)
        return 1
    print("Changed Rust lines are formatted; full-repository debt is reported separately.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
