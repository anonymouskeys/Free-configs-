#!/usr/bin/env python3
"""Generate classified subscription files from parsed proxy share links.

Country detection is deliberately offline and privacy-preserving. It uses only
country flags, ISO codes and country names already present in each profile name.
No DNS, GeoIP or third-party API requests are performed. Profiles without
reliable metadata are placed in countries/unknown.txt.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from normalize_configs import NormalizedConfig, normalize_config, normalize_transport
from subscription_parser import ParsedConfig, parse_subscription

COUNTRIES: dict[str, tuple[str, tuple[str, ...]]] = {
    "AE": ("United Arab Emirates", ("uae", "united arab emirates", "emirates")),
    "AR": ("Argentina", ("argentina",)),
    "AT": ("Austria", ("austria",)),
    "AU": ("Australia", ("australia",)),
    "BE": ("Belgium", ("belgium",)),
    "BG": ("Bulgaria", ("bulgaria",)),
    "BR": ("Brazil", ("brazil",)),
    "CA": ("Canada", ("canada",)),
    "CH": ("Switzerland", ("switzerland", "swiss")),
    "CL": ("Chile", ("chile",)),
    "CN": ("China", ("china",)),
    "CZ": ("Czechia", ("czechia", "czech republic", "czech")),
    "DE": ("Germany", ("germany", "deutschland")),
    "DK": ("Denmark", ("denmark",)),
    "EE": ("Estonia", ("estonia",)),
    "ES": ("Spain", ("spain",)),
    "FI": ("Finland", ("finland",)),
    "FR": ("France", ("france",)),
    "GB": ("United Kingdom", ("united kingdom", "great britain", "britain", "england", "uk")),
    "GR": ("Greece", ("greece",)),
    "HK": ("Hong Kong", ("hong kong", "hongkong")),
    "HR": ("Croatia", ("croatia",)),
    "HU": ("Hungary", ("hungary",)),
    "ID": ("Indonesia", ("indonesia",)),
    "IE": ("Ireland", ("ireland",)),
    "IL": ("Israel", ("israel",)),
    "IN": ("India", ("india",)),
    "IS": ("Iceland", ("iceland",)),
    "IT": ("Italy", ("italy",)),
    "JP": ("Japan", ("japan",)),
    "KR": ("South Korea", ("south korea", "korea")),
    "KZ": ("Kazakhstan", ("kazakhstan",)),
    "LT": ("Lithuania", ("lithuania",)),
    "LU": ("Luxembourg", ("luxembourg",)),
    "LV": ("Latvia", ("latvia",)),
    "MD": ("Moldova", ("moldova",)),
    "MX": ("Mexico", ("mexico",)),
    "MY": ("Malaysia", ("malaysia",)),
    "NL": ("Netherlands", ("netherlands", "holland")),
    "NO": ("Norway", ("norway",)),
    "NZ": ("New Zealand", ("new zealand",)),
    "PH": ("Philippines", ("philippines",)),
    "PL": ("Poland", ("poland",)),
    "PT": ("Portugal", ("portugal",)),
    "RO": ("Romania", ("romania",)),
    "RS": ("Serbia", ("serbia",)),
    "RU": ("Russia", ("russia", "russian federation")),
    "SE": ("Sweden", ("sweden",)),
    "SG": ("Singapore", ("singapore",)),
    "SI": ("Slovenia", ("slovenia",)),
    "SK": ("Slovakia", ("slovakia",)),
    "TH": ("Thailand", ("thailand",)),
    "TR": ("Türkiye", ("turkiye", "turkey")),
    "TW": ("Taiwan", ("taiwan",)),
    "UA": ("Ukraine", ("ukraine",)),
    "US": ("United States", ("united states", "united states of america", "usa", "america")),
    "VN": ("Vietnam", ("vietnam", "viet nam")),
    "ZA": ("South Africa", ("south africa",)),
}

FLAG_TO_CODE = {
    "".join(chr(0x1F1E6 + ord(char) - ord("A")) for char in code): code
    for code in COUNTRIES
}
TOKEN_RE = re.compile(r"(?<![A-Za-z])([A-Z]{2})(?![A-Za-z])")


@dataclass
class CatalogResult:
    configs: list[NormalizedConfig]
    input_count: int
    duplicate_count: int
    issue_count: int
    protocol_counts: dict[str, int]
    transport_counts: dict[str, int]
    country_counts: dict[str, int]


def detect_country(config: ParsedConfig) -> tuple[str, str]:
    """Infer a country from the original profile label, or return Unknown."""
    label = (config.name or "").strip()
    folded = label.casefold().replace("_", " ").replace("-", " ")

    for flag, code in FLAG_TO_CODE.items():
        if flag in label:
            return code, COUNTRIES[code][0]

    # Country names are stronger than two-letter tokens and are checked first.
    for code, (name, aliases) in COUNTRIES.items():
        if any(re.search(rf"(?<!\w){re.escape(alias)}(?!\w)", folded) for alias in aliases):
            return code, name

    for match in TOKEN_RE.finditer(label):
        code = match.group(1).upper()
        if code in COUNTRIES:
            return code, COUNTRIES[code][0]

    return "UN", "Unknown"


def transport_buckets(config: NormalizedConfig) -> set[str]:
    """Return only controlled bucket names; never derive filenames from raw labels."""
    buckets: set[str] = set()
    transport = normalize_transport(config.transport)
    buckets.add(transport or "unknown")

    if config.security == "reality":
        buckets.add("reality")
        if config.flow and "vision" in config.flow.lower():
            buckets.add("reality-vision")
    return buckets


def protocol_buckets(config: NormalizedConfig) -> set[str]:
    buckets = {config.protocol}
    if config.protocol in {"hysteria", "hysteria2"}:
        buckets.add("hysteria-all")
    return buckets


def build_catalog(payload: str) -> CatalogResult:
    parsed = parse_subscription(payload)
    configs: list[NormalizedConfig] = []
    seen: set[str] = set()
    duplicates = 0

    for raw_config in parsed.configs:
        code, name = detect_country(raw_config)
        normalized = normalize_config(raw_config, code, name)
        if normalized.fingerprint in seen:
            duplicates += 1
            continue
        seen.add(normalized.fingerprint)
        configs.append(normalized)

    configs.sort(key=lambda item: (item.protocol, item.country_code, item.host or "", item.port or 0, item.fingerprint))

    protocol_counts: Counter[str] = Counter()
    transport_counts: Counter[str] = Counter()
    country_counts: Counter[str] = Counter()
    for config in configs:
        for bucket in protocol_buckets(config):
            protocol_counts[bucket] += 1
        for bucket in transport_buckets(config):
            transport_counts[bucket] += 1
        country_counts[config.country_code.lower() if config.country_code != "UN" else "unknown"] += 1

    return CatalogResult(
        configs=configs,
        input_count=len(parsed.configs),
        duplicate_count=duplicates,
        issue_count=len(parsed.issues),
        protocol_counts=dict(sorted(protocol_counts.items())),
        transport_counts=dict(sorted(transport_counts.items())),
        country_counts=dict(sorted(country_counts.items())),
    )


def _write_lines(path: Path, configs: Iterable[NormalizedConfig]) -> None:
    values = [item.link for item in configs]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(values) + ("\n" if values else ""), encoding="utf-8", newline="\n")


def write_catalog(catalog: CatalogResult, output_dir: Path, status_document: dict[str, object]) -> None:
    """Replace the complete generated tree so obsolete category files vanish."""
    output_dir = output_dir.resolve()
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}-", dir=output_dir.parent))

    try:
        _write_lines(staging / "all.txt", catalog.configs)

        protocols: dict[str, list[NormalizedConfig]] = defaultdict(list)
        transports: dict[str, list[NormalizedConfig]] = defaultdict(list)
        countries: dict[str, list[NormalizedConfig]] = defaultdict(list)

        for config in catalog.configs:
            for bucket in protocol_buckets(config):
                protocols[bucket].append(config)
            for bucket in transport_buckets(config):
                transports[bucket].append(config)
            country_key = config.country_code.lower() if config.country_code != "UN" else "unknown"
            countries[country_key].append(config)

        for name, configs in protocols.items():
            filename = "hysteria.txt" if name == "hysteria-all" else f"{name}.txt"
            _write_lines(staging / "protocol" / filename, configs)
        for name, configs in transports.items():
            _write_lines(staging / "transport" / f"{name}.txt", configs)
        for name, configs in countries.items():
            _write_lines(staging / "countries" / f"{name}.txt", configs)

        (staging / "status.json").write_text(
            json.dumps(status_document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )

        backup = output_dir.with_name(output_dir.name + ".old")
        if backup.exists():
            shutil.rmtree(backup)
        if output_dir.exists():
            output_dir.replace(backup)
        staging.replace(output_dir)
        if backup.exists():
            shutil.rmtree(backup)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _read_inputs(paths: Iterable[str]) -> str:
    values = list(paths)
    if not values:
        return sys.stdin.read()
    return "\n".join(Path(value).read_text(encoding="utf-8-sig") for value in values)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate classified config subscriptions")
    parser.add_argument("files", nargs="*", help="Input files; stdin when omitted")
    parser.add_argument("--output-dir", default="output")
    args = parser.parse_args()

    try:
        catalog = build_catalog(_read_inputs(args.files))
        summary = {
            "input_configs": catalog.input_count,
            "final_configs": len(catalog.configs),
            "duplicates_removed": catalog.duplicate_count,
            "invalid_configs": catalog.issue_count,
            "protocols": catalog.protocol_counts,
            "transports": catalog.transport_counts,
            "countries": catalog.country_counts,
        }
        write_catalog(catalog, Path(args.output_dir), {"summary": summary, "sources": []})
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        print(f"generation error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if catalog.configs else 3


if __name__ == "__main__":
    raise SystemExit(main())
