#!/usr/bin/env python3
"""Reduce raw CGSS process logcat to a strict shareable diagnostic timeline.

Raw logcat can contain URLs, identifiers, headers, certificate details and other
private/proprietary values. This helper emits only timestamp/category/severity.
It never copies tag, PID/TID, message text, exception text, hostname, URL or any
matched substring into the output.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable, TextIO

_EPOCH_RE = re.compile(r"^\s*(?P<time>\d{9,}(?:\.\d+)?)\s+")

# Ordered most-specific-first. Only category IDs leave this process.
_RULES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "process_crash",
        "fatal",
        re.compile(r"fatal exception|fatal signal|abort message|sigsegv|sigabrt", re.I),
    ),
    (
        "anr",
        "fatal",
        re.compile(r"\banr\b|input dispatching timed out", re.I),
    ),
    (
        "tls_certificate_error",
        "error",
        re.compile(
            r"certpathvalidatorexception|sslpeerunverifiedexception|"
            r"certificate[_ ]verify[_ ]failed|certificate verify failed|"
            r"trust anchor for certification path not found|unknown ca",
            re.I,
        ),
    ),
    (
        "tls_handshake_error",
        "error",
        re.compile(r"sslhandshakeexception|ssl_connect|tls alert|handshake failed", re.I),
    ),
    (
        "dns_error",
        "error",
        re.compile(r"unknownhostexception|could not resolve host|name or service not known", re.I),
    ),
    (
        "connection_refused",
        "error",
        re.compile(r"connection refused|failed to connect|couldn't connect", re.I),
    ),
    (
        "network_unreachable",
        "error",
        re.compile(r"network is unreachable|no route to host", re.I),
    ),
    (
        "network_timeout",
        "error",
        re.compile(r"sockettimeoutexception|timeout was reached|timed out", re.I),
    ),
    (
        "http_error",
        "error",
        re.compile(r"\bhttp(?:/\d(?:\.\d)?)?\s+[45]\d\d\b|response code\s*[45]\d\d", re.I),
    ),
    (
        "unity_web_request_error",
        "error",
        re.compile(r"unitywebrequest.*(?:error|failed)|curl error", re.I),
    ),
    (
        "process_exit",
        "warning",
        re.compile(r"process .* has died|killing .* process|process terminated", re.I),
    ),
)

_ALLOWED_KEYS = frozenset({"schema", "time", "source", "category", "severity"})


def classify(line: str) -> tuple[str, str] | None:
    for category, severity, pattern in _RULES:
        if pattern.search(line):
            return category, severity
    return None


def sanitize_lines(lines: Iterable[str]) -> tuple[list[dict[str, object]], Counter[str]]:
    events: list[dict[str, object]] = []
    counts: Counter[str] = Counter()
    for line in lines:
        classified = classify(line)
        if classified is None:
            continue
        timestamp_match = _EPOCH_RE.match(line)
        # Runtime timelines must be numerically mergeable. With `logcat -v epoch`
        # every useful line has this prefix; skip malformed lines rather than
        # inventing ordering metadata.
        if timestamp_match is None:
            counts["classified_without_epoch"] += 1
            continue
        category, severity = classified
        event: dict[str, object] = {
            "schema": 1,
            "time": float(timestamp_match.group("time")),
            "source": "device_logcat",
            "category": category,
            "severity": severity,
        }
        if set(event) != _ALLOWED_KEYS:
            raise RuntimeError("sanitized device event schema drift")
        events.append(event)
        counts[category] += 1
    return events, counts


def write_events(events: Iterable[dict[str, object]], stream: TextIO) -> int:
    count = 0
    for event in events:
        if set(event) != _ALLOWED_KEYS:
            raise ValueError("refusing non-whitelisted device event fields")
        stream.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
        stream.flush()
        count += 1
    return count


def _iter_stream(stream: TextIO):
    for line in stream:
        yield line


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sanitize raw `adb logcat -v epoch` into category-only device evidence"
    )
    parser.add_argument("input", help="raw logcat path or '-' for stdin")
    parser.add_argument("-o", "--output", type=Path, required=True)
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    input_stream: TextIO
    should_close = False
    if args.input == "-":
        input_stream = sys.stdin
    else:
        input_stream = Path(args.input).open("r", encoding="utf-8", errors="replace")
        should_close = True

    counts: Counter[str] = Counter()
    written = 0
    try:
        # Stream rather than retain raw lines or messages in memory longer than
        # needed. Classify one line, discard it, emit only whitelisted metadata.
        with args.output.open("w", encoding="utf-8") as output:
            for line in _iter_stream(input_stream):
                classified = classify(line)
                if classified is None:
                    continue
                timestamp_match = _EPOCH_RE.match(line)
                if timestamp_match is None:
                    counts["classified_without_epoch"] += 1
                    continue
                category, severity = classified
                event = {
                    "schema": 1,
                    "time": float(timestamp_match.group("time")),
                    "source": "device_logcat",
                    "category": category,
                    "severity": severity,
                }
                if set(event) != _ALLOWED_KEYS:
                    raise RuntimeError("sanitized device event schema drift")
                output.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
                output.flush()
                counts[category] += 1
                written += 1
    finally:
        if should_close:
            input_stream.close()

    # Summary is aggregate-only and safe for terminal transcripts.
    print(
        json.dumps(
            {"events": written, "categories": dict(sorted(counts.items()))},
            sort_keys=True,
        ),
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
