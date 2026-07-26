#!/usr/bin/env python3
import base64
import json
import unittest
from pathlib import Path
import sys
from urllib.parse import unquote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from normalize_configs import normalize_subscription  # noqa: E402


def b64(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")


class NormalizationTests(unittest.TestCase):
    def test_deduplicates_links_with_different_names_and_query_order(self) -> None:
        one = (
            "vless://id@EXAMPLE.com:443?security=reality&type=grpc&flow=xtls-rprx-vision#Old"
        )
        two = (
            "vless://id@example.com:443?flow=xtls-rprx-vision&type=grpc&security=reality#Other"
        )
        result = normalize_subscription(one + "\n" + two)
        self.assertEqual(2, result.input_count)
        self.assertEqual(1, result.duplicate_count)
        self.assertEqual(1, len(result.configs))
        self.assertEqual("Reality Vision", result.configs[0].feature)
        self.assertEqual("🌍 Unknown | Reality Vision | @anonymouskeys", result.configs[0].name)

    def test_vmess_name_is_replaced_and_duplicate_ignored(self) -> None:
        base = {
            "v": "2", "ps": "Advertising", "add": "VMESS.EXAMPLE.COM", "port": "443",
            "id": "00000000-0000-0000-0000-000000000001", "aid": "0", "net": "WS", "tls": "TLS"
        }
        other = dict(base)
        other["ps"] = "Another name"
        payload = "vmess://" + b64(json.dumps(base)) + "\nvmess://" + b64(json.dumps(other))
        result = normalize_subscription(payload)
        self.assertEqual(1, len(result.configs))
        encoded = result.configs[0].link[len("vmess://"):]
        decoded = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode()
        data = json.loads(decoded)
        self.assertEqual("🌍 Unknown | WebSocket | @anonymouskeys", data["ps"])
        self.assertEqual("vmess.example.com", data["add"])
        self.assertEqual("ws", data["net"])

    def test_shadowsocks_is_canonical_sip002(self) -> None:
        legacy = "ss://" + b64("aes-256-gcm:password@SS.EXAMPLE.COM:8388") + "#Old"
        result = normalize_subscription(legacy)
        self.assertEqual(1, len(result.configs))
        item = result.configs[0]
        self.assertTrue(item.link.startswith("ss://"))
        self.assertIn("@ss.example.com:8388#", item.link)
        self.assertIn("%40anonymouskeys", item.link)

    def test_different_credentials_are_not_duplicates(self) -> None:
        payload = (
            "trojan://one@example.com:443?type=tcp#A\n"
            "trojan://two@example.com:443?type=tcp#B"
        )
        result = normalize_subscription(payload)
        self.assertEqual(2, len(result.configs))
        self.assertEqual(0, result.duplicate_count)

    def test_hy2_alias_is_normalized(self) -> None:
        result = normalize_subscription("hy2://auth@EXAMPLE.com:443/?insecure=1#Old")
        self.assertEqual("hysteria2", result.configs[0].protocol)
        self.assertTrue(result.configs[0].link.startswith("hysteria2://"))

    def test_invalid_entries_do_not_abort(self) -> None:
        payload = "vmess://bad\nvless://id@example.com:443?type=tcp"
        result = normalize_subscription(payload)
        self.assertEqual(1, len(result.configs))
        self.assertEqual(1, result.issue_count)


if __name__ == "__main__":
    unittest.main()
