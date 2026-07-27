#!/usr/bin/env python3
"""Download private subscription sources and publish sanitized aggregate output.

Source URLs are read only from SOURCE_SUB_01..SOURCE_SUB_20 environment
variables. Logs and generated status files use numeric source identifiers only.
A failed source never aborts the batch while at least one source yields valid
configs.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from generate_outputs import build_catalog, write_catalog
from subscription_parser import decode_subscription, parse_subscription

SOURCE_LIMIT = 20
USER_AGENT = "FreeConfigsHub/1.0"
DEFAULT_TIMEOUT = 25
DEFAULT_RETRIES = 3
MAX_DOWNLOAD_BYTES = 25 * 1024 * 1024


@dataclass(frozen=True)
class SourceStatus:
    source: str
    ok: bool
    status: str
    configs: int = 0


@dataclass(frozen=True)
class DownloadedSource:
    number: int
    payload: str
    config_count: int


class DownloadError(RuntimeError):
    def __init__(self, public_status: str):
        super().__init__(public_status)
        self.public_status = public_status


def source_name(number: int) -> str:
    return f"Source {number:02d}"


def configured_sources(environ: dict[str, str] | None = None) -> list[tuple[int, str]]:
    env = os.environ if environ is None else environ
    result: list[tuple[int, str]] = []
    for number in range(1, SOURCE_LIMIT + 1):
        value = env.get(f"SOURCE_SUB_{number:02d}", "").strip()
        if value:
            result.append((number, value))
    return result


def classify_error(exc: BaseException) -> str:
    if isinstance(exc, HTTPError):
        return f"HTTP {exc.code}"
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return "timeout"
    if isinstance(exc, URLError):
        reason = exc.reason
        if isinstance(reason, (TimeoutError, socket.timeout)):
            return "timeout"
        return "network error"
    return "download error"


def download_text(
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    opener: Callable[..., object] = urlopen,
) -> str:
    last_error: BaseException | None = None
    request = Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/plain, application/octet-stream, */*",
        },
    )

    for attempt in range(1, retries + 1):
        try:
            with opener(request, timeout=timeout) as response:
                length_header = response.headers.get("Content-Length")
                if length_header and int(length_header) > MAX_DOWNLOAD_BYTES:
                    raise DownloadError("too large")
                raw = response.read(MAX_DOWNLOAD_BYTES + 1)
                if len(raw) > MAX_DOWNLOAD_BYTES:
                    raise DownloadError("too large")
                if not raw:
                    raise DownloadError("empty response")
                try:
                    return raw.decode("utf-8-sig")
                except UnicodeDecodeError:
                    return raw.decode("utf-8", errors="replace")
        except DownloadError:
            raise
        except (HTTPError, URLError, TimeoutError, socket.timeout, OSError) as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(min(2 ** (attempt - 1), 4))

    raise DownloadError(classify_error(last_error or RuntimeError()))


def process_source(
    number: int,
    url: str,
    downloader: Callable[[str], str] = download_text,
) -> DownloadedSource:
    try:
        raw = downloader(url)
    except DownloadError:
        raise
    except BaseException as exc:
        raise DownloadError(classify_error(exc)) from exc

    decoded, _layers = decode_subscription(raw)
    parsed = parse_subscription(decoded)
    if not parsed.configs:
        raise DownloadError("no valid configs")

    return DownloadedSource(
        number=number,
        payload=decoded,
        config_count=len(parsed.configs),
    )


def generate_outputs(
    downloaded: list[DownloadedSource],
    statuses: list[SourceStatus],
    output_dir: Path,
) -> dict[str, object]:
    aggregate = "\n".join(item.payload for item in downloaded)
    catalog = build_catalog(aggregate)
    if not catalog.configs:
        raise RuntimeError("No normalized configurations were produced")

    summary: dict[str, object] = {
        "configured_sources": len(statuses),
        "successful_sources": sum(1 for item in statuses if item.ok),
        "failed_sources": sum(1 for item in statuses if not item.ok),
        "input_configs": catalog.input_count,
        "final_configs": len(catalog.configs),
        "duplicates_removed": catalog.duplicate_count,
        "invalid_configs": catalog.issue_count,
        "protocols": catalog.protocol_counts,
        "transports": catalog.transport_counts,
        "countries": catalog.country_counts,
    }
    status_document = {
        "summary": summary,
        "sources": [asdict(item) for item in statuses],
    }
    write_catalog(catalog, output_dir, status_document)
    return summary


def print_status(status: SourceStatus) -> None:
    if status.ok:
        print(f"{status.source:<10} ✅ {status.configs} configs")
    else:
        print(f"{status.source:<10} ❌ {status.status}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Update sanitized config hub outputs")
    parser.add_argument("--output-dir", default="output")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES)
    args = parser.parse_args()

    sources = configured_sources()
    if not sources:
        print("No SOURCE_SUB_XX secrets are configured.", file=sys.stderr)
        return 2

    downloaded: list[DownloadedSource] = []
    statuses: list[SourceStatus] = []

    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("🐉 Free Configs Hub")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    for number, url in sources:
        label = source_name(number)
        try:
            item = process_source(
                number,
                url,
                downloader=lambda current_url: download_text(
                    current_url,
                    timeout=args.timeout,
                    retries=args.retries,
                ),
            )
            downloaded.append(item)
            status = SourceStatus(label, True, "ok", item.config_count)
        except DownloadError as exc:
            status = SourceStatus(label, False, exc.public_status, 0)

        statuses.append(status)
        print_status(status)

    if not downloaded:
        print("All configured sources failed; existing outputs were left untouched.", file=sys.stderr)
        return 3

    try:
        summary = generate_outputs(downloaded, statuses, Path(args.output_dir))
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Output generation failed: {exc}", file=sys.stderr)
        return 4

    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"Sources:    {summary['successful_sources']}/{summary['configured_sources']}")
    print(f"Input:      {summary['input_configs']}")
    print(f"Duplicates: {summary['duplicates_removed']}")
    print(f"Invalid:    {summary['invalid_configs']}")
    print(f"Final:      {summary['final_configs']}")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
