#!/usr/bin/env python3
import base64
import json
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from subscription_parser import parse_subscription  # noqa: E402


def b64(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")


class SubscriptionParserTests(unittest.TestCase):
    def test_plain_mixed_subscription(self) -> None:
        vmess = {
            "v": "2",
            "ps": "vmess node",
            "add": "vmess.example.com",
            "port": "443",
            "id": "00000000-0000-0000-0000-000000000001",
            "aid": "0",
            "net": "ws",
            "tls": "tls",
        }
        payload = "\n".join(
            [
                "vless://00000000-0000-0000-0000-000000000002@vless.example.com:443"
                "?type=grpc&security=reality&flow=xtls-rprx-vision#VLESS",
                "vmess://" + b64(json.dumps(vmess)),
                "trojan://secret@trojan.example.com:443?security=tls&type=tcp#Trojan",
                "hysteria://auth@hy1.example.com:443?sni=example.com#HY1",
                "hy2://auth@hy2.example.com:8443/?insecure=1#HY2",
            ]
        )
        result = parse_subscription(payload)
        self.assertEqual(5, len(result.configs))
        self.assertEqual(0, len(result.issues))
        self.assertEqual(
            ["vless", "vmess", "trojan", "hysteria", "hysteria2"],
            [item.protocol for item in result.configs],
        )
        self.assertEqual("grpc", result.configs[0].transport)
        self.assertEqual("reality", result.configs[0].security)
        self.assertEqual("xtls-rprx-vision", result.configs[0].flow)

    def test_base64_subscription(self) -> None:
        plain = (
            "vless://00000000-0000-0000-0000-000000000003"
            "@example.com:443?type=tcp&security=tls#Node"
        )
        result = parse_subscription(b64(plain))
        self.assertEqual(1, result.decoded_layers)
        self.assertEqual(1, len(result.configs))

    def test_nested_base64_subscription(self) -> None:
        plain = "trojan://password@example.com:443?type=grpc#Node"
        result = parse_subscription(b64(b64(plain)))
        self.assertEqual(2, result.decoded_layers)
        self.assertEqual(1, len(result.configs))

    def test_shadowsocks_sip002_and_legacy(self) -> None:
        credentials = b64("aes-256-gcm:password")
        modern = f"ss://{credentials}@ss.example.com:8388#Modern"
        legacy = "ss://" + b64("chacha20-ietf-poly1305:pass@legacy.example.com:443")
        result = parse_subscription(modern + "\n" + legacy)
        self.assertEqual(2, len(result.configs))
        self.assertEqual(0, len(result.issues))
        self.assertEqual("aes-256-gcm", result.configs[0].security)

    def test_invalid_entry_does_not_abort_batch(self) -> None:
        payload = (
            "vless://id@example.com:443?type=tcp\n"
            "vmess://definitely-not-json\n"
            "trojan://password@example.org:443"
        )
        result = parse_subscription(payload)
        self.assertEqual(2, len(result.configs))
        self.assertEqual(1, len(result.issues))
        self.assertIn("VMess", result.issues[0].error)

    def test_duplicates_are_preserved_for_stage_three(self) -> None:
        link = "vless://id@example.com:443?type=tcp"
        result = parse_subscription(link + "\n" + link)
        # Extraction removes byte-identical duplicates. Semantic deduplication is Stage 3.
        self.assertEqual(1, len(result.configs))


if __name__ == "__main__":
    unittest.main()
