#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from generate_outputs import build_catalog, detect_country, write_catalog  # noqa: E402
from subscription_parser import parse_link  # noqa: E402


class GeneratorTests(unittest.TestCase):
    def test_country_from_flag_and_name(self) -> None:
        flagged = parse_link("vless://id@de.example:443?type=grpc#🇩🇪 Fast")
        named = parse_link("trojan://pw@us.example:443#United States node")
        self.assertEqual(("DE", "Germany"), detect_country(flagged))
        self.assertEqual(("US", "United States"), detect_country(named))

    def test_unknown_without_reliable_metadata(self) -> None:
        item = parse_link("vless://id@1.1.1.1:443?type=tcp#Fast node")
        self.assertEqual(("UN", "Unknown"), detect_country(item))

    def test_catalog_classifies_protocol_transport_reality_and_country(self) -> None:
        payload = "\n".join([
            "vless://id@de.example:443?type=grpc&security=reality&flow=xtls-rprx-vision#🇩🇪 Germany",
            "trojan://pw@unknown.example:443?type=ws#No country",
            "hy2://auth@fi.example:8443#Finland",
        ])
        catalog = build_catalog(payload)
        self.assertEqual(3, len(catalog.configs))
        self.assertEqual(1, catalog.protocol_counts["vless"])
        self.assertEqual(1, catalog.protocol_counts["hysteria2"])
        self.assertEqual(1, catalog.protocol_counts["hysteria-all"])
        self.assertEqual(1, catalog.transport_counts["grpc"])
        self.assertEqual(1, catalog.transport_counts["reality"])
        self.assertEqual(1, catalog.transport_counts["reality-vision"])
        self.assertEqual(1, catalog.country_counts["de"])
        self.assertEqual(1, catalog.country_counts["fi"])
        self.assertEqual(1, catalog.country_counts["unknown"])

    def test_write_catalog_creates_tree_and_removes_stale_files(self) -> None:
        payload = "\n".join([
            "vless://id@de.example:443?type=grpc&security=reality#🇩🇪 Germany",
            "trojan://pw@unknown.example:443?type=ws#No country",
        ])
        catalog = build_catalog(payload)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            output.mkdir()
            (output / "stale.txt").write_text("old")
            status = {"summary": {"final_configs": 2}, "sources": []}
            write_catalog(catalog, output, status)

            self.assertTrue((output / "all.txt").is_file())
            self.assertTrue((output / "protocol" / "vless.txt").is_file())
            self.assertTrue((output / "protocol" / "trojan.txt").is_file())
            self.assertTrue((output / "transport" / "grpc.txt").is_file())
            self.assertTrue((output / "transport" / "reality.txt").is_file())
            self.assertTrue((output / "countries" / "de.txt").is_file())
            self.assertTrue((output / "countries" / "unknown.txt").is_file())
            self.assertFalse((output / "stale.txt").exists())
            self.assertEqual(2, json.loads((output / "status.json").read_text())["summary"]["final_configs"])

    def test_malformed_transport_cannot_become_a_filename(self) -> None:
        payload = (
            "vless://id@example.com:443?"
            "type=tcp%23%F0%9F%92%A190%40oneclickvpnkeys#Foreign"
        )
        catalog = build_catalog(payload)
        self.assertEqual({"tcp": 1}, catalog.transport_counts)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            write_catalog(catalog, output, {"summary": {}, "sources": []})
            names = {path.name for path in (output / "transport").iterdir()}
            self.assertEqual({"tcp.txt"}, names)
            self.assertNotIn("oneclickvpnkeys", (output / "all.txt").read_text().lower())


if __name__ == "__main__":
    unittest.main()
