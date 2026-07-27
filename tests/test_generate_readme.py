#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from generate_readme import generate_readme, raw_url  # noqa: E402


class ReadmeGeneratorTests(unittest.TestCase):
    def test_readme_contains_dynamic_counts_links_and_community(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            (output / "protocol").mkdir(parents=True)
            (output / "transport").mkdir()
            (output / "countries").mkdir()
            (output / "all.txt").write_text("one\ntwo\n", encoding="utf-8")
            (output / "protocol" / "vless.txt").write_text("one\n", encoding="utf-8")
            (output / "transport" / "ws.txt").write_text("one\ntwo\n", encoding="utf-8")
            (output / "countries" / "de.txt").write_text("one\n", encoding="utf-8")
            (output / "status.json").write_text(json.dumps({
                "updated_at_utc": "2026-07-27T05:00:00Z",
                "summary": {
                    "configured_sources": 7,
                    "successful_sources": 7,
                    "failed_sources": 0,
                    "input_configs": 3,
                    "final_configs": 2,
                    "duplicates_removed": 1,
                    "invalid_configs": 0,
                },
            }), encoding="utf-8")

            readme = generate_readme(output)

        self.assertIn("Anonymous Keys", readme)
        self.assertIn("t.me/anonymouskeys", readme)
        self.assertIn("| VLESS | `1` |", readme)
        self.assertIn("| WebSocket | `2` |", readme)
        self.assertIn("🇩🇪 Germany", readme)
        self.assertIn("2026-07-27T05:00:00Z", readme)
        self.assertIn("UQCeZHtAYYkCOeJW26HkXgdT4f", readme)
        self.assertIn("TYUFWzRdicVgUgAf5HCPTVGHr6", readme)

    def test_raw_url_uses_expected_repository(self) -> None:
        self.assertEqual(
            "https://raw.githubusercontent.com/anonymouskeys/Free-configs-/main/output/all.txt",
            raw_url("output/all.txt"),
        )


if __name__ == "__main__":
    unittest.main()
