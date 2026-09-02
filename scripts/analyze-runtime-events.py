#!/usr/bin/env python3
"""Analyze sanitized cgss-relive runtime event logs and compare profile runs.

Input must be JSONL emitted by ``server.safe_events.SafeEventLog``.  The tool
accepts only the documented sanitized event shape; raw request/response captures
or unexpected fields are rejected instead of being copied into reports.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

FINAL_RESOURCE_VERSION = "10133800"

_ALLOWED_EVENT_KEYS = {
    "time",
    "route",
    "status",
    "headers",
    "api_candidates",
    "request_keys",
    "response_keys",
    "response_data_keys",
    "response_data_headers",
    "error",
}
_ALLOWED_HEADERS = {"APP-VER", "RES-VER", "X-Unity-Version"}
_ALLOWED_RESPONSE_HEADERS = {"result_code", "required_res_ver", "app_ver"}
_ALLOWED_API_CANDIDATE_KEYS = {"group", "key", "name", "literal_index"}


class UnsafeEventLog(ValueError):
    """Raised when a JSONL file is not the documented sanitized event format."""


@dataclass(frozen=True)
class EventSignature:
    route: str
    status: int
    error: str | None
    res_ver: str | None
    result_code: int | None


def _expect_string_list(value: Any, field: str) -> None:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise UnsafeEventLog(f"{field} must be a list of strings")


def validate_event(value: Any, *, line_number: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise UnsafeEventLog(f"line {line_number}: event must be an object")
    unknown = set(value) - _ALLOWED_EVENT_KEYS
    if unknown:
        raise UnsafeEventLog(f"line {line_number}: unexpected event fields: {sorted(unknown)}")
    if not isinstance(value.get("route"), str):
        raise UnsafeEventLog(f"line {line_number}: route must be a string")
    if not isinstance(value.get("status"), int):
        raise UnsafeEventLog(f"line {line_number}: status must be an integer")
    if "time" in value and not isinstance(value["time"], (int, float)):
        raise UnsafeEventLog(f"line {line_number}: time must be numeric")
    if "error" in value and not isinstance(value["error"], str):
        raise UnsafeEventLog(f"line {line_number}: error must be a string")

    headers = value.get("headers")
    if headers is not None:
        if not isinstance(headers, dict) or set(headers) - _ALLOWED_HEADERS:
            raise UnsafeEventLog(f"line {line_number}: headers are not in the sanitized allow-list")
        if any(not isinstance(item, str) for item in headers.values()):
            raise UnsafeEventLog(f"line {line_number}: sanitized header values must be strings")

    response_headers = value.get("response_data_headers")
    if response_headers is not None:
        if not isinstance(response_headers, dict) or set(response_headers) - _ALLOWED_RESPONSE_HEADERS:
            raise UnsafeEventLog(
                f"line {line_number}: response_data_headers are not in the sanitized allow-list"
            )
        if "result_code" in response_headers and not isinstance(response_headers["result_code"], int):
            raise UnsafeEventLog(f"line {line_number}: result_code must be an integer")
        for field in ("required_res_ver", "app_ver"):
            if field in response_headers and not isinstance(response_headers[field], (str, int)):
                raise UnsafeEventLog(f"line {line_number}: {field} must be a scalar")

    for field in ("request_keys", "response_keys", "response_data_keys"):
        if field in value:
            _expect_string_list(value[field], f"line {line_number}: {field}")

    candidates = value.get("api_candidates")
    if candidates is not None:
        if not isinstance(candidates, list):
            raise UnsafeEventLog(f"line {line_number}: api_candidates must be a list")
        for candidate in candidates:
            if not isinstance(candidate, dict) or set(candidate) != _ALLOWED_API_CANDIDATE_KEYS:
                raise UnsafeEventLog(f"line {line_number}: malformed api_candidates entry")
            if not isinstance(candidate["group"], str) or not isinstance(candidate["name"], str):
                raise UnsafeEventLog(f"line {line_number}: malformed api candidate strings")
            if not isinstance(candidate["key"], int) or not isinstance(candidate["literal_index"], int):
                raise UnsafeEventLog(f"line {line_number}: malformed api candidate integers")
    return value


def load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise UnsafeEventLog(f"could not read {path}: {exc}") from exc
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise UnsafeEventLog(f"line {line_number}: invalid JSON: {exc.msg}") from exc
        events.append(validate_event(value, line_number=line_number))
    return events


def _response_result(event: Mapping[str, Any]) -> int | None:
    headers = event.get("response_data_headers")
    if isinstance(headers, Mapping):
        value = headers.get("result_code")
        if isinstance(value, int):
            return value
    return None


def signature(event: Mapping[str, Any]) -> EventSignature:
    headers = event.get("headers")
    res_ver = headers.get("RES-VER") if isinstance(headers, Mapping) else None
    return EventSignature(
        route=str(event["route"]),
        status=int(event["status"]),
        error=str(event["error"]) if "error" in event else None,
        res_ver=str(res_ver) if res_ver is not None else None,
        result_code=_response_result(event),
    )


def analyze_events(events: list[Mapping[str, Any]]) -> dict[str, Any]:
    routes = [str(event["route"]) for event in events]
    check_indices = [index for index, route in enumerate(routes) if route == "/load/check"]
    index_indices = [index for index, route in enumerate(routes) if route == "/load/index"]

    resource_214_indices = [
        index
        for index in check_indices
        if _response_result(events[index]) == 214
    ]
    final_retry_indices: list[int] = []
    final_success_indices: list[int] = []
    for index in check_indices:
        event = events[index]
        headers = event.get("headers")
        res_ver = headers.get("RES-VER") if isinstance(headers, Mapping) else None
        if str(res_ver) != FINAL_RESOURCE_VERSION:
            continue
        final_retry_indices.append(index)
        if _response_result(event) == 1:
            final_success_indices.append(index)

    server_returned_214 = bool(resource_214_indices)
    observed_retry_after_214 = any(
        retry_index > result_index
        for result_index in resource_214_indices
        for retry_index in final_retry_indices
    )
    server_returned_final_success = bool(final_success_indices)
    observed_followup_after_final_success = any(
        success_index + 1 < len(events)
        for success_index in final_success_indices
    )

    first_failure: dict[str, Any] | None = None
    for index, event in enumerate(events):
        if int(event["status"]) >= 400 or event.get("error"):
            first_failure = {
                "event_index": index,
                "route": event["route"],
                "status": event["status"],
            }
            if event.get("error"):
                first_failure["error"] = event["error"]
            if event.get("api_candidates"):
                first_failure["api_candidates"] = event["api_candidates"]
            break

    after_load_index: dict[str, Any] | None = None
    if index_indices:
        last_index = index_indices[-1]
        if last_index + 1 < len(events):
            event = events[last_index + 1]
            after_load_index = {
                "event_index": last_index + 1,
                "route": event["route"],
                "status": event["status"],
            }
            if event.get("error"):
                after_load_index["error"] = event["error"]
            if event.get("api_candidates"):
                after_load_index["api_candidates"] = event["api_candidates"]

    phase = "no_http_request"
    if events:
        phase = "http_reached"
    if check_indices:
        phase = "load_check_reached"
    if observed_retry_after_214:
        phase = "resource_retry_observed"
    if server_returned_final_success:
        phase = "final_resource_check_responded"
    if "/load/title" in routes:
        phase = "load_title_reached"
    if index_indices:
        phase = "load_index_reached"
    if after_load_index is not None:
        phase = "post_load_index_observed"

    return {
        "events": len(events),
        "phase": phase,
        "resource_negotiation": {
            "server_returned_214": server_returned_214,
            "observed_10133800_retry_after_214": observed_retry_after_214,
            "server_returned_success_for_10133800": server_returned_final_success,
            "observed_followup_request_after_10133800_success": observed_followup_after_final_success,
        },
        "reached": {
            "load_check": bool(check_indices),
            "load_title": "/load/title" in routes,
            "load_index": bool(index_indices),
        },
        "first_failure": first_failure,
        "after_load_index": after_load_index,
        "sequence": [
            {
                "route": sig.route,
                "status": sig.status,
                **({"error": sig.error} if sig.error is not None else {}),
                **({"res_ver": sig.res_ver} if sig.res_ver is not None else {}),
                **({"result_code": sig.result_code} if sig.result_code is not None else {}),
            }
            for sig in (signature(event) for event in events)
        ],
    }


def compare_runs(runs: list[tuple[str, list[Mapping[str, Any]]]]) -> dict[str, Any] | None:
    if len(runs) < 2:
        return None
    signatures = [[signature(event) for event in events] for _, events in runs]
    common = min(len(items) for items in signatures)
    divergence = common
    for index in range(common):
        if any(items[index] != signatures[0][index] for items in signatures[1:]):
            divergence = index
            break

    states: dict[str, Any] = {}
    for (label, _), items in zip(runs, signatures):
        states[label] = None
        if divergence < len(items):
            states[label] = {
                "route": items[divergence].route,
                "status": items[divergence].status,
                "error": items[divergence].error,
                "res_ver": items[divergence].res_ver,
                "result_code": items[divergence].result_code,
            }
    return {
        "common_prefix_events": divergence,
        "divergence_event_index": divergence,
        "states": states,
    }


def _parse_run(value: str) -> tuple[str, Path]:
    if "=" in value:
        label, raw_path = value.split("=", 1)
        if not label or not raw_path:
            raise argparse.ArgumentTypeError("run must be LABEL=PATH or PATH")
        return label, Path(raw_path)
    path = Path(value)
    return path.stem, path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze sanitized cgss-relive runtime event JSONL and compare profile runs"
    )
    parser.add_argument("runs", nargs="+", type=_parse_run, metavar="[LABEL=]EVENTS.jsonl")
    parser.add_argument("-o", "--output", type=Path, help="optional JSON report path")
    args = parser.parse_args()

    loaded: list[tuple[str, list[dict[str, Any]]]] = []
    try:
        for label, path in args.runs:
            if any(existing == label for existing, _ in loaded):
                raise UnsafeEventLog(f"duplicate run label: {label}")
            loaded.append((label, load_events(path)))
    except UnsafeEventLog as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = {
        "schema": 1,
        "final_resource_version": FINAL_RESOURCE_VERSION,
        "runs": {label: analyze_events(events) for label, events in loaded},
        "comparison": compare_runs(loaded),
    }
    text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
