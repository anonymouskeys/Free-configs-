#!/usr/bin/env python3
import json
import os
import tempfile
import unittest
from pathlib import Path
import sys
from urllib.error import HTTPError, URLError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from update_hub import (  # noqa: E402
    DownloadError,
    SourceStatus,
    configured_sources,
    generate_outputs,
    process_source,
)


class UpdateHubTests(unittest.TestCase):
    def test_configured_sources_are_numeric_and_skip_empty_values(self) -> None:
        env = {
            "SOURCE_SUB_01": "https://secret.invalid/one",
            "SOURCE_SUB_02": " ",
            "SOURCE_SUB_07": "https://secret.invalid/seven",
        }
        self.assertEqual(
            [(1, env["SOURCE_SUB_01"]), (7, env["SOURCE_SUB_07"])],
            configured_sources(env),
        )

    def test_plain_source_is_accepted(self) -> None:
        link = "vless://id@example.com:443?type=tcp#Old"
        item = process_source(1, "secret", downloader=lambda _url: link)
        self.assertEqual(1, item.config_count)
        self.assertNotIn("secret", item.payload)

    def test_base64_source_is_decoded_before_aggregation(self) -> None:
        import base64
        link = "trojan://password@example.com:443?type=grpc#Old"
        encoded = base64.b64encode(link.encode()).decode()
        item = process_source(2, "secret", downloader=lambda _url: encoded)
        self.assertEqual(1, item.config_count)
        self.assertIn("trojan://", item.payload)

    def test_invalid_source_is_skipped(self) -> None:
        with self.assertRaisesRegex(DownloadError, "no valid configs"):
            process_source(3, "secret", downloader=lambda _url: "not a subscription")

    def test_outputs_contain_no_source_urls_or_original_names(self) -> None:
        payload = (
            "vless://id@example.com:443?security=reality&type=grpc#Advertising\n"
            "vless://id@example.com:443?type=grpc&security=reality#Different"
        )
        downloaded = [process_source(1, "https://hidden.invalid", downloader=lambda _url: payload)]
        statuses = [SourceStatus("Source 01", True, "ok", 2)]

        with tempfile.TemporaryDirectory() as directory:
            summary = generate_outputs(downloaded, statuses, Path(directory))
            links = Path(directory, "all.txt").read_text(encoding="utf-8")
            status = Path(directory, "status.json").read_text(encoding="utf-8")

        self.assertEqual(1, summary["final_configs"])
        self.assertEqual(1, summary["duplicates_removed"])
        self.assertIn("%40anonymouskeys", links)
        self.assertNotIn("Advertising", links)
        self.assertNotIn("hidden.invalid", links)
        self.assertNotIn("hidden.invalid", status)
        parsed_status = json.loads(status)
        self.assertEqual("Source 01", parsed_status["sources"][0]["source"])


if __name__ == "__main__":
    unittest.main()
