#!/usr/bin/env python3
"""Exercise the formatting gate with real rustfmt and disposable Git fixtures."""

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.dont_write_bytecode = True
SCRIPT = Path(__file__).with_name("check_rustfmt_changed_lines.py")
SPEC = importlib.util.spec_from_file_location("format_gate", SCRIPT)
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)

INHERITED_DEBT = "const   OLD:u8=1;\n\n"
FORMATTED = "pub fn probe(cond: bool) {\n    let _ = cond;\n}\n"


class FormattingGateTests(unittest.TestCase):
    def setUp(self):
        # This is a standalone Git-only fixture, never a workspace checkout.
        # Retain it for failure inspection; CI runners dispose of their temp dir.
        self.root = Path(tempfile.mkdtemp(prefix="mls-rustfmt-gate-test-"))
        self.source = self.root / "probe.rs"
        self.source.write_text(INHERITED_DEBT + FORMATTED)
        self.git("init", "--quiet")
        self.git("add", "probe.rs")
        self.git("-c", "user.name=Formatting test", "-c", "user.email=ci@example.invalid",
                 "commit", "--quiet", "-m", "Immutable test baseline")
        self.base = self.git("rev-parse", "HEAD").strip()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, text=True)

    def assert_gate(self, expected):
        output = io.StringIO()
        previous_directory = Path.cwd()
        try:
            os.chdir(self.root)
            # The production bootstrap remains fixed in the checker. A new
            # standalone fixture uses its own immutable ancestor for this test.
            with patch.object(GATE, "KNOWN_FORMAT_BASELINE", self.base), \
                 patch.object(sys, "argv", [str(SCRIPT), "--base", self.base]), \
                 contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                result = GATE.main()
        finally:
            os.chdir(previous_directory)
        self.assertEqual(result, expected, f"Fixture: {self.root}\n{output.getvalue()}")

    def test_identical_inherited_debt_survives_a_formatted_edit(self):
        self.source.write_text(INHERITED_DEBT + FORMATTED.replace("= cond", "= !cond"))
        self.assert_gate(0)

    def test_new_unformatted_line_is_rejected(self):
        self.source.write_text(INHERITED_DEBT + "pub fn probe(cond: bool) {let _ = cond;}\n")
        self.assert_gate(1)

    def test_new_formatted_file_is_accepted(self):
        (self.root / "new.rs").write_text(FORMATTED)
        self.git("add", "--intent-to-add", "new.rs")
        self.assert_gate(0)

    def test_missing_final_newline_is_rejected(self):
        self.source.write_text(INHERITED_DEBT + FORMATTED.rstrip("\n"))
        self.assert_gate(1)

    def test_invalid_syntax_is_rejected(self):
        self.source.write_text("pub fn probe( {\n")
        self.assert_gate(2)

    def test_context_change_cannot_hide_new_indentation_debt(self):
        self.source.write_text(INHERITED_DEBT +
                               "pub fn probe(cond: bool) {\n    if cond {\n    let _ = cond;\n    }\n}\n")
        self.assert_gate(1)

    def test_correctly_indented_context_change_is_accepted(self):
        self.source.write_text(INHERITED_DEBT +
                               "pub fn probe(cond: bool) {\n    if cond {\n        let _ = cond;\n    }\n}\n")
        self.assert_gate(0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
