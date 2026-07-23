from __future__ import annotations

import unittest

from server.tests import generate_mls_chat_contract_vectors as generator


class ControlCorpusGeneratorTests(unittest.TestCase):
    def test_semantic_source_rejects_duplicate_json_keys(self) -> None:
        source = generator.SOURCE_PATH.read_text(encoding="utf-8")
        duplicate = source.replace(
            '  "schemaVersion": 1,',
            '  "schemaVersion": 1,\n  "schemaVersion": 1,',
            1,
        ).encode("utf-8")
        with self.assertRaisesRegex(ValueError, "duplicate JSON key 'schemaVersion'"):
            generator.render_target(
                generator.TARGET_PATH.read_text(encoding="utf-8"), duplicate
            )


if __name__ == "__main__":
    unittest.main()
