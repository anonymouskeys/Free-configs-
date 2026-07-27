#!/usr/bin/env python3
"""Normalize, rename and semantically deduplicate parsed proxy links.

Stage 3 intentionally does not perform GeoIP lookups. A caller may supply a
country code/name later; otherwise profiles are branded as Unknown.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

from subscription_parser import ParsedConfig, parse_subscription, _decode_base64

BRAND = "@anonymouskeys"
COUNTRY_FLAGS = {
    "DE": "🇩🇪", "NL": "🇳🇱", "FI": "🇫🇮", "US": "🇺🇸", "RU": "🇷🇺",
    "FR": "🇫🇷", "GB": "🇬🇧", "CA": "🇨🇦", "JP": "🇯🇵", "SG": "🇸🇬",
    "TR": "🇹🇷", "PL": "🇵🇱", "SE": "🇸🇪", "CH": "🇨🇭", "AT": "🇦🇹",
}
COUNTRY_NAMES = {
    "DE": "Germany", "NL": "Netherlands", "FI": "Finland", "US": "United States",
    "RU": "Russia", "FR": "France", "GB": "United Kingdom", "CA": "Canada",
    "JP": "Japan", "SG": "Singapore", "TR": "Türkiye", "PL": "Poland",
    "SE": "Sweden", "CH": "Switzerland", "AT": "Austria",
}
KNOWN_TRANSPORTS = (
    "httpupgrade", "splithttp", "xhttp", "grpc", "quic", "raw", "kcp",
    "websocket", "ws", "http", "tcp",
)
TRANSPORT_ALIASES = {
    "websocket": "ws",
    "http-upgrade": "httpupgrade",
    "http_upgrade": "httpupgrade",
    "h2": "http",
}

LOWERCASE_QUERY_KEYS = {
    "type", "network", "security", "flow", "headerType", "encryption",
    "fp", "mode", "serviceName", "alpn", "packetEncoding",
}


@dataclass(frozen=True)
class NormalizedConfig:
    protocol: str
    link: str
    fingerprint: str
    host: str | None
    port: int | None
    transport: str | None
    security: str | None
    flow: str | None
    feature: str
    country_code: str
    country_name: str
    name: str


@dataclass
class NormalizeResult:
    configs: list[NormalizedConfig]
    input_count: int
    duplicate_count: int
    issue_count: int
    decoded_layers: int


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _format_host(host: str) -> str:
    host = host.lower().rstrip(".")
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def _country(code: str | None, name: str | None) -> tuple[str, str, str]:
    normalized = (code or "UN").upper()
    if normalized == "UN":
        return "UN", name or "Unknown", "🌍"
    return normalized, name or COUNTRY_NAMES.get(normalized, normalized), COUNTRY_FLAGS.get(normalized, "🌐")


def normalize_transport(value: str | None) -> str | None:
    """Return a stable transport token and discard appended labels/advertising.

    Some public lists contain malformed values such as ``type=tcp#channel`` or
    ``type=ws<emoji>@channel``.  Prefix matching is intentional here: it repairs
    the known transport token without allowing the remainder to become an output
    filename.  Unknown values remain unclassified.
    """
    if not value:
        return None
    folded = unquote(str(value)).strip().casefold()
    folded = TRANSPORT_ALIASES.get(folded, folded)
    for token in KNOWN_TRANSPORTS:
        if folded.startswith(token):
            return TRANSPORT_ALIASES.get(token, token)
    return None


def feature_label(config: ParsedConfig) -> str:
    security = (config.security or "").lower()
    flow = (config.flow or "").lower()
    transport = normalize_transport(config.transport) or ""
    if security == "reality" and "vision" in flow:
        return "Reality Vision"
    if security == "reality":
        return "Reality"
    if transport:
        aliases = {
            "grpc": "gRPC", "xhttp": "XHTTP", "httpupgrade": "HTTPUpgrade",
            "ws": "WebSocket", "tcp": "TCP", "quic": "QUIC",
        }
        return aliases.get(transport, transport.upper())
    return config.protocol.upper()


def branded_name(config: ParsedConfig, country_code: str | None = None, country_name: str | None = None) -> tuple[str, str, str]:
    code, name, flag = _country(country_code, country_name)
    return f"{flag} {name} | {feature_label(config)} | {BRAND}", code, name


def _normalized_query(query: str) -> str:
    pairs = []
    for key, value in parse_qsl(query, keep_blank_values=True):
        key = key.strip()
        value = value.strip()
        if not key or value == "":
            continue
        if key in {"type", "network"}:
            transport = normalize_transport(value)
            if transport is None:
                continue
            value = transport
        elif key in LOWERCASE_QUERY_KEYS:
            value = value.lower()
        pairs.append((key, value))
    pairs.sort(key=lambda item: (item[0].lower(), item[1]))
    return urlencode(pairs, doseq=True, safe="/:,@")


def _standard_link(config: ParsedConfig, name: str) -> tuple[str, str]:
    parsed = urlsplit(config.raw)
    if not parsed.hostname or parsed.port is None:
        raise ValueError("missing host or port")
    scheme = "hysteria2" if parsed.scheme.lower() == "hy2" else parsed.scheme.lower()
    host = _format_host(parsed.hostname)
    userinfo = ""
    if parsed.username is not None:
        userinfo = quote(unquote(parsed.username), safe="-._~!$&'()*+,;=:") + "@"
    netloc = f"{userinfo}{host}:{parsed.port}"
    path = parsed.path or ""
    query = _normalized_query(parsed.query)
    canonical_without_name = urlunsplit((scheme, netloc, path, query, ""))
    link = urlunsplit((scheme, netloc, path, query, quote(name, safe="")))
    return link, canonical_without_name


def _vmess_link(config: ParsedConfig, name: str) -> tuple[str, str]:
    encoded = config.raw[len("vmess://"):].split("#", 1)[0].strip()
    decoded = _decode_base64(encoded)
    if decoded is None:
        raise ValueError("invalid VMess Base64")
    data = json.loads(decoded)
    if not isinstance(data, dict):
        raise ValueError("invalid VMess JSON")

    normalized = dict(data)
    normalized["add"] = str(normalized.get("add", "")).strip().lower().rstrip(".")
    normalized["port"] = str(int(str(normalized.get("port", "0"))))
    for key in ("tls", "type", "scy"):
        if key in normalized and isinstance(normalized[key], str):
            normalized[key] = normalized[key].strip().lower()
    transport = normalize_transport(str(normalized.get("net", "")))
    if transport:
        normalized["net"] = transport
    else:
        normalized.pop("net", None)
    normalized["ps"] = name

    fingerprint_data = dict(normalized)
    fingerprint_data.pop("ps", None)
    fingerprint_json = json.dumps(fingerprint_data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    output_json = json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "vmess://" + _b64url(output_json.encode()), "vmess://" + _b64url(fingerprint_json.encode())


def _ss_link(config: ParsedConfig, name: str) -> tuple[str, str]:
    raw = config.raw[len("ss://"):]
    body, _, _fragment = raw.partition("#")
    main, sep, query = body.partition("?")

    if "@" in main:
        encoded_credentials, endpoint = main.rsplit("@", 1)
        credentials = _decode_base64(unquote(encoded_credentials))
    else:
        decoded = _decode_base64(unquote(main))
        if decoded is None or "@" not in decoded:
            raise ValueError("invalid Shadowsocks payload")
        credentials, endpoint = decoded.rsplit("@", 1)

    if credentials is None or ":" not in credentials:
        raise ValueError("invalid Shadowsocks credentials")
    endpoint_parts = urlsplit("ss://x@" + endpoint)
    if not endpoint_parts.hostname or endpoint_parts.port is None:
        raise ValueError("missing Shadowsocks host or port")

    credentials_encoded = _b64url(credentials.encode())
    host = _format_host(endpoint_parts.hostname)
    normalized_query = _normalized_query(query if sep else "")
    base = f"ss://{credentials_encoded}@{host}:{endpoint_parts.port}"
    if normalized_query:
        base += "?" + normalized_query
    return base + "#" + quote(name, safe=""), base


def normalize_config(config: ParsedConfig, country_code: str | None = None, country_name: str | None = None) -> NormalizedConfig:
    name, code, country = branded_name(config, country_code, country_name)
    if config.protocol == "vmess":
        link, fingerprint_source = _vmess_link(config, name)
    elif config.protocol == "ss":
        link, fingerprint_source = _ss_link(config, name)
    else:
        link, fingerprint_source = _standard_link(config, name)

    fingerprint = hashlib.sha256(fingerprint_source.encode("utf-8")).hexdigest()
    return NormalizedConfig(
        protocol=config.protocol,
        link=link,
        fingerprint=fingerprint,
        host=config.host.lower().rstrip(".") if config.host else None,
        port=config.port,
        transport=normalize_transport(config.transport),
        security=config.security.lower() if config.security else None,
        flow=config.flow,
        feature=feature_label(config),
        country_code=code,
        country_name=country,
        name=name,
    )


def normalize_subscription(payload: str) -> NormalizeResult:
    parsed = parse_subscription(payload)
    unique: list[NormalizedConfig] = []
    seen: set[str] = set()
    duplicates = 0

    for item in parsed.configs:
        normalized = normalize_config(item)
        if normalized.fingerprint in seen:
            duplicates += 1
            continue
        seen.add(normalized.fingerprint)
        unique.append(normalized)

    return NormalizeResult(
        configs=unique,
        input_count=len(parsed.configs),
        duplicate_count=duplicates,
        issue_count=len(parsed.issues),
        decoded_layers=parsed.decoded_layers,
    )


def _read_inputs(paths: Iterable[str]) -> str:
    values = list(paths)
    if not values:
        return sys.stdin.read()
    return "\n".join(Path(value).read_text(encoding="utf-8-sig") for value in values)


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize, brand and deduplicate proxy subscriptions")
    parser.add_argument("files", nargs="*", help="Input files; stdin when omitted")
    parser.add_argument("--format", choices=("json", "jsonl", "links"), default="json")
    args = parser.parse_args()

    try:
        payload = _read_inputs(args.files)
        result = normalize_subscription(payload)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        print(f"normalization error: {exc}", file=sys.stderr)
        return 1

    if args.format == "links":
        for item in result.configs:
            print(item.link)
    elif args.format == "jsonl":
        for item in result.configs:
            print(json.dumps(asdict(item), ensure_ascii=False, sort_keys=True))
    else:
        print(json.dumps({
            "input_count": result.input_count,
            "output_count": len(result.configs),
            "duplicate_count": result.duplicate_count,
            "issue_count": result.issue_count,
            "decoded_layers": result.decoded_layers,
            "configs": [asdict(item) for item in result.configs],
        }, ensure_ascii=False, indent=2, sort_keys=True))

    return 0 if result.configs else 3


if __name__ == "__main__":
    raise SystemExit(main())
