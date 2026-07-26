#!/usr/bin/env python3
"""Parse proxy subscription payloads without network access.

Supported share-link schemes:
- vless://
- vmess:// (base64-encoded JSON)
- trojan://
- ss:// (SIP002 legacy and modern forms)
- hysteria://
- hysteria2://
- hy2://

The parser accepts plain text, standard/url-safe Base64 subscriptions, and
one additional nested Base64 layer. Invalid entries are skipped and reported
without aborting the complete batch.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qs, unquote, urlsplit

SUPPORTED_SCHEMES = {
    "vless",
    "vmess",
    "trojan",
    "ss",
    "hysteria",
    "hysteria2",
    "hy2",
}
LINK_PATTERN = re.compile(
    r"(?i)(?:vless|vmess|trojan|ss|hysteria2|hysteria|hy2)://[^\s<>\"']+"
)
BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/_=-]+$")


@dataclass(frozen=True)
class ParsedConfig:
    protocol: str
    raw: str
    host: str | None = None
    port: int | None = None
    name: str = ""
    transport: str | None = None
    security: str | None = None
    flow: str | None = None
    valid: bool = True
    error: str | None = None


@dataclass(frozen=True)
class ParseIssue:
    value: str
    error: str


@dataclass
class ParseResult:
    configs: list[ParsedConfig]
    issues: list[ParseIssue]
    decoded_layers: int = 0


def _restore_padding(value: str) -> str:
    return value + ("=" * (-len(value) % 4))


def _decode_base64(value: str) -> str | None:
    compact = "".join(value.split())
    if len(compact) < 8 or not BASE64_PATTERN.fullmatch(compact):
        return None

    padded = _restore_padding(compact)
    candidates: list[bytes] = []
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            if decoder is base64.b64decode:
                candidates.append(decoder(padded, validate=True))
            else:
                candidates.append(decoder(padded))
        except (binascii.Error, ValueError):
            continue

    for raw in candidates:
        if not raw or b"\x00" in raw:
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
        if printable / max(len(text), 1) >= 0.95:
            return text
    return None


def decode_subscription(payload: str, max_layers: int = 2) -> tuple[str, int]:
    """Decode a whole subscription when it looks like Base64.

    Decoding is conservative: a layer is accepted only when the decoded value
    contains a supported URI, another plausible Base64 payload, or line breaks.
    """
    current = payload.lstrip("\ufeff").strip()
    layers = 0

    for _ in range(max_layers):
        if LINK_PATTERN.search(current):
            break
        decoded = _decode_base64(current)
        if decoded is None:
            break
        if not (
            LINK_PATTERN.search(decoded)
            or "\n" in decoded
            or _decode_base64(decoded) is not None
        ):
            break
        current = decoded.strip()
        layers += 1

    return current, layers


def extract_links(text: str) -> list[str]:
    """Extract supported links while preserving first-seen order."""
    found: list[str] = []
    seen: set[str] = set()

    for match in LINK_PATTERN.finditer(text):
        link = match.group(0).rstrip(".,;)]}")
        if link not in seen:
            seen.add(link)
            found.append(link)
    return found


def _parse_port(value: object) -> int:
    try:
        port = int(str(value))
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid or missing port") from exc
    if not 1 <= port <= 65535:
        raise ValueError("port outside 1..65535")
    return port


def _name_from_fragment(fragment: str) -> str:
    return unquote(fragment or "").strip()


def _first(query: dict[str, list[str]], key: str) -> str | None:
    values = query.get(key)
    return values[0] if values else None


def _parse_standard_uri(link: str, protocol: str) -> ParsedConfig:
    parsed = urlsplit(link)
    if not parsed.hostname:
        raise ValueError("missing host")
    port = _parse_port(parsed.port)
    query = parse_qs(parsed.query, keep_blank_values=True)

    transport = _first(query, "type") or _first(query, "network")
    security = _first(query, "security")
    flow = _first(query, "flow")

    if protocol in {"hysteria", "hysteria2"} and transport is None:
        transport = "quic"

    return ParsedConfig(
        protocol=protocol,
        raw=link,
        host=parsed.hostname,
        port=port,
        name=_name_from_fragment(parsed.fragment),
        transport=transport.lower() if transport else None,
        security=security.lower() if security else None,
        flow=flow,
    )


def _parse_vmess(link: str) -> ParsedConfig:
    encoded = link[len("vmess://") :].split("#", 1)[0].strip()
    decoded = _decode_base64(encoded)
    if decoded is None:
        raise ValueError("VMess payload is not valid Base64")

    try:
        data = json.loads(decoded)
    except json.JSONDecodeError as exc:
        raise ValueError("VMess payload is not valid JSON") from exc
    if not isinstance(data, dict):
        raise ValueError("VMess JSON must be an object")

    host = str(data.get("add", "")).strip()
    if not host:
        raise ValueError("missing host")

    return ParsedConfig(
        protocol="vmess",
        raw=link,
        host=host,
        port=_parse_port(data.get("port")),
        name=str(data.get("ps", "")).strip(),
        transport=str(data.get("net", "")).strip().lower() or None,
        security=str(data.get("tls", "")).strip().lower() or None,
    )


def _parse_ss(link: str) -> ParsedConfig:
    body = link[len("ss://") :]
    body_without_fragment, _, fragment = body.partition("#")
    main, _, query_string = body_without_fragment.partition("?")
    query = parse_qs(query_string, keep_blank_values=True)

    # SIP002 modern form: base64(method:password)@host:port
    if "@" in main:
        userinfo, endpoint = main.rsplit("@", 1)
        credentials = _decode_base64(unquote(userinfo))
        if credentials is None or ":" not in credentials:
            raise ValueError("invalid Shadowsocks credentials")
        method, password = credentials.split(":", 1)
        endpoint_uri = urlsplit(f"ss://x@{endpoint}")
    else:
        # Legacy form: base64(method:password@host:port)
        decoded = _decode_base64(unquote(main))
        if decoded is None or "@" not in decoded:
            raise ValueError("invalid Shadowsocks payload")
        credentials, endpoint = decoded.rsplit("@", 1)
        if ":" not in credentials:
            raise ValueError("invalid Shadowsocks credentials")
        method, password = credentials.split(":", 1)
        endpoint_uri = urlsplit(f"ss://x@{endpoint}")

    if not method or not password:
        raise ValueError("empty Shadowsocks method or password")
    if not endpoint_uri.hostname:
        raise ValueError("missing host")

    plugin = _first(query, "plugin")
    return ParsedConfig(
        protocol="ss",
        raw=link,
        host=endpoint_uri.hostname,
        port=_parse_port(endpoint_uri.port),
        name=_name_from_fragment(fragment),
        transport=f"plugin:{plugin.split(';', 1)[0]}" if plugin else None,
        security=method,
    )


def parse_link(link: str) -> ParsedConfig:
    scheme = link.split("://", 1)[0].lower()
    if scheme not in SUPPORTED_SCHEMES:
        raise ValueError(f"unsupported scheme: {scheme}")

    if scheme == "vmess":
        return _parse_vmess(link)
    if scheme == "ss":
        return _parse_ss(link)

    protocol = "hysteria2" if scheme == "hy2" else scheme
    return _parse_standard_uri(link, protocol)


def parse_subscription(payload: str) -> ParseResult:
    decoded, layers = decode_subscription(payload)
    links = extract_links(decoded)
    configs: list[ParsedConfig] = []
    issues: list[ParseIssue] = []

    for link in links:
        try:
            configs.append(parse_link(link))
        except (ValueError, TypeError) as exc:
            issues.append(ParseIssue(value=link, error=str(exc)))

    if not links and decoded.strip():
        issues.append(ParseIssue(value="<payload>", error="no supported share links found"))

    return ParseResult(configs=configs, issues=issues, decoded_layers=layers)


def _read_inputs(paths: Iterable[str]) -> str:
    values = list(paths)
    if not values:
        return sys.stdin.read()

    chunks: list[str] = []
    for value in values:
        chunks.append(Path(value).read_text(encoding="utf-8-sig"))
    return "\n".join(chunks)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Parse plain or Base64 proxy subscription payloads."
    )
    parser.add_argument("files", nargs="*", help="Input files; stdin is used when omitted")
    parser.add_argument(
        "--format",
        choices=("json", "jsonl", "links"),
        default="json",
        help="Output format (default: json)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Return exit code 2 when at least one entry is invalid",
    )
    args = parser.parse_args()

    try:
        payload = _read_inputs(args.files)
    except (OSError, UnicodeError) as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return 1

    result = parse_subscription(payload)

    if args.format == "links":
        for config in result.configs:
            print(config.raw)
    elif args.format == "jsonl":
        for config in result.configs:
            print(json.dumps(asdict(config), ensure_ascii=False, sort_keys=True))
    else:
        print(
            json.dumps(
                {
                    "decoded_layers": result.decoded_layers,
                    "config_count": len(result.configs),
                    "issue_count": len(result.issues),
                    "configs": [asdict(item) for item in result.configs],
                    "issues": [asdict(item) for item in result.issues],
                },
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )

    if args.strict and result.issues:
        return 2
    return 0 if result.configs else 3


if __name__ == "__main__":
    raise SystemExit(main())
