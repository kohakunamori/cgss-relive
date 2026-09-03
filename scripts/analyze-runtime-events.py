#!/usr/bin/env python3
"""Analyze sanitized cgss-relive runtime evidence and compare profile runs.

Control/resource JSONL must use ``server.safe_events.SafeEventLog``'s strict
schema. Independent server streams can be merged by timestamp with repeated
``--merge-run LABEL=PATH``.

Optional ``--device-log LABEL=PATH`` accepts only the category-only output of
``scripts/sanitize-device-logcat.py``. Device diagnostics are attached to the
matching run but never enter the HTTP/resource sequence, phase machine, or
cross-run signature comparison. This prevents a logcat line from fabricating
network progress while still surfacing TLS/crash/ANR evidence.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

FINAL_RESOURCE_VERSION = "10133800"
RESOURCE_ROUTE_PREFIX = "@resource/"

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
_ALLOWED_DEVICE_KEYS = {"schema", "time", "source", "category", "severity"}
_ALLOWED_DEVICE_CATEGORIES = {
    "process_crash",
    "anr",
    "tls_certificate_error",
    "tls_handshake_error",
    "dns_error",
    "connection_refused",
    "network_unreachable",
    "network_timeout",
    "http_error",
    "unity_web_request_error",
    "process_exit",
}
_ALLOWED_DEVICE_SEVERITIES = {"warning", "error", "fatal"}


class UnsafeEventLog(ValueError):
    """Raised when a JSONL file is not one of the documented sanitized formats."""


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

    route = value["route"]
    if route.startswith(RESOURCE_ROUTE_PREFIX):
        allowed_resource_routes = {
            "@resource/manifest",
            "@resource/AssetBundles",
            "@resource/Sound",
            "@resource/Movie",
            "@resource/Generic",
            "@resource/unresolved",
        }
        if route not in allowed_resource_routes:
            raise UnsafeEventLog(f"line {line_number}: unsupported sanitized resource route")

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


def validate_device_event(value: Any, *, line_number: int) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _ALLOWED_DEVICE_KEYS:
        raise UnsafeEventLog(f"device line {line_number}: event is not the strict device schema")
    if value.get("schema") != 1:
        raise UnsafeEventLog(f"device line {line_number}: unsupported schema")
    if value.get("source") != "device_logcat":
        raise UnsafeEventLog(f"device line {line_number}: unsupported source")
    if not isinstance(value.get("time"), (int, float)):
        raise UnsafeEventLog(f"device line {line_number}: time must be numeric")
    if value.get("category") not in _ALLOWED_DEVICE_CATEGORIES:
        raise UnsafeEventLog(f"device line {line_number}: unsupported category")
    if value.get("severity") not in _ALLOWED_DEVICE_SEVERITIES:
        raise UnsafeEventLog(f"device line {line_number}: unsupported severity")
    return value


def _load_jsonl(path: Path) -> list[Any]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise UnsafeEventLog(f"could not read {path}: {exc}") from exc
    values: list[Any] = []
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            values.append((line_number, json.loads(line)))
        except json.JSONDecodeError as exc:
            raise UnsafeEventLog(f"line {line_number}: invalid JSON: {exc.msg}") from exc
    return values


def load_events(path: Path) -> list[dict[str, Any]]:
    return [validate_event(value, line_number=line) for line, value in _load_jsonl(path)]


def load_device_events(path: Path) -> list[dict[str, Any]]:
    return [
        validate_device_event(value, line_number=line)
        for line, value in _load_jsonl(path)
    ]


def merge_event_streams(streams: list[list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Merge sanitized control/resource streams by numeric timestamp."""
    tagged: list[tuple[float, int, int, dict[str, Any]]] = []
    for source_index, events in enumerate(streams):
        for event_index, event in enumerate(events):
            timestamp = event.get("time")
            if not isinstance(timestamp, (int, float)):
                raise UnsafeEventLog("merged event streams require numeric time on every event")
            tagged.append((float(timestamp), source_index, event_index, event))
    tagged.sort(key=lambda item: (item[0], item[1], item[2]))
    return [event for _, _, _, event in tagged]


def merge_device_streams(streams: list[list[dict[str, Any]]]) -> list[dict[str, Any]]:
    events = [event for stream in streams for event in stream]
    events.sort(key=lambda event: float(event["time"]))
    return events


def analyze_device_events(events: list[Mapping[str, Any]]) -> dict[str, Any]:
    categories = Counter(str(event["category"]) for event in events)
    severities = Counter(str(event["severity"]) for event in events)
    first_event = None
    if events:
        event = min(events, key=lambda item: float(item["time"]))
        first_event = {
            "time": float(event["time"]),
            "category": str(event["category"]),
            "severity": str(event["severity"]),
        }
    first_failure = None
    for event in sorted(events, key=lambda item: float(item["time"])):
        if event["severity"] in {"error", "fatal"}:
            first_failure = {
                "time": float(event["time"]),
                "category": str(event["category"]),
                "severity": str(event["severity"]),
            }
            break
    return {
        "events": len(events),
        "categories": dict(sorted(categories.items())),
        "severities": dict(sorted(severities.items())),
        "first_event": first_event,
        "first_failure": first_failure,
        "has_tls_error": bool(
            categories["tls_certificate_error"] or categories["tls_handshake_error"]
        ),
        "has_process_crash": bool(categories["process_crash"]),
        "has_anr": bool(categories["anr"]),
        "has_network_error": any(
            categories[name]
            for name in (
                "dns_error",
                "connection_refused",
                "network_unreachable",
                "network_timeout",
                "http_error",
                "unity_web_request_error",
            )
        ),
    }


def _response_header(event: Mapping[str, Any], name: str) -> Any:
    headers = event.get("response_data_headers")
    if isinstance(headers, Mapping):
        return headers.get(name)
    return None


def _response_result(event: Mapping[str, Any]) -> int | None:
    value = _response_header(event, "result_code")
    return value if isinstance(value, int) else None


def _request_res_ver(event: Mapping[str, Any]) -> str | None:
    headers = event.get("headers")
    if not isinstance(headers, Mapping):
        return None
    value = headers.get("RES-VER")
    return str(value) if value is not None else None


def signature(event: Mapping[str, Any]) -> EventSignature:
    return EventSignature(
        route=str(event["route"]),
        status=int(event["status"]),
        error=str(event["error"]) if "error" in event else None,
        res_ver=_request_res_ver(event),
        result_code=_response_result(event),
    )


def _has_later_event(indices: list[int], event_count: int) -> bool:
    return any(index + 1 < event_count for index in indices)


def _has_later_index(first_indices: list[int], later_indices: list[int]) -> bool:
    return any(later > first for first in first_indices for later in later_indices)


def analyze_events(events: list[Mapping[str, Any]]) -> dict[str, Any]:
    routes = [str(event["route"]) for event in events]
    check_indices = [index for index, route in enumerate(routes) if route == "/load/check"]
    index_indices = [index for index, route in enumerate(routes) if route == "/load/index"]
    resource_indices = [
        index for index, route in enumerate(routes) if route.startswith(RESOURCE_ROUTE_PREFIX)
    ]
    resource_success_indices = [
        index
        for index in resource_indices
        if routes[index] != "@resource/unresolved" and int(events[index]["status"]) < 400
    ]
    manifest_indices = [index for index, route in enumerate(routes) if route == "@resource/manifest"]

    resource_214_indices = [index for index in check_indices if _response_result(events[index]) == 214]
    final_check_indices = [
        index for index in check_indices if _request_res_ver(events[index]) == FINAL_RESOURCE_VERSION
    ]
    final_success_indices = [
        index for index in final_check_indices if _response_result(events[index]) == 1
    ]
    direct_success_indices = [
        index
        for index in check_indices
        if _response_result(events[index]) == 1
        and _request_res_ver(events[index]) != FINAL_RESOURCE_VERSION
        and str(_response_header(events[index], "required_res_ver")) == FINAL_RESOURCE_VERSION
    ]

    observed_later_control_after_214 = any(
        later > first and not routes[later].startswith(RESOURCE_ROUTE_PREFIX)
        for first in resource_214_indices
        for later in range(len(events))
    )
    observed_later_resource_after_214 = _has_later_index(resource_214_indices, resource_indices)
    observed_later_successful_resource_after_214 = _has_later_index(
        resource_214_indices, resource_success_indices
    )
    observed_later_final_check_after_214 = _has_later_index(resource_214_indices, final_check_indices)
    observed_followup_after_direct_success = _has_later_event(direct_success_indices, len(events))
    observed_followup_after_final_success = _has_later_event(final_success_indices, len(events))

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
    if resource_214_indices:
        phase = "resource_version_214_responded"
    if direct_success_indices:
        phase = "old_resource_direct_success_responded"
    if final_check_indices:
        phase = "final_version_load_check_observed"
    if final_success_indices:
        phase = "final_version_load_check_responded"
    if resource_indices:
        phase = "resource_plane_observed"
    if resource_success_indices:
        phase = "resource_plane_served"
    if index_indices:
        phase = "load_index_reached"
    if after_load_index is not None:
        phase = "post_load_index_observed"

    return {
        "events": len(events),
        "phase": phase,
        "resource_negotiation": {
            "server_returned_214": bool(resource_214_indices),
            "observed_later_control_request_after_214": observed_later_control_after_214,
            "observed_resource_request_after_214": observed_later_resource_after_214,
            "observed_successful_resource_response_after_214": observed_later_successful_resource_after_214,
            "observed_later_10133800_load_check_after_214": observed_later_final_check_after_214,
            "server_returned_direct_success_with_required_res_ver": bool(direct_success_indices),
            "observed_followup_request_after_direct_success": observed_followup_after_direct_success,
            "server_returned_success_for_10133800": bool(final_success_indices),
            "observed_followup_request_after_10133800_success": observed_followup_after_final_success,
        },
        "reached": {
            "load_check": bool(check_indices),
            "load_title": "/load/title" in routes,
            "resource_plane": bool(resource_indices),
            "resource_manifest": bool(manifest_indices),
            "load_index": bool(index_indices),
        },
        "resource_plane": {
            "events": len(resource_indices),
            "successful_events": len(resource_success_indices),
            "routes": sorted({routes[index] for index in resource_indices}),
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


def _parse_label_path(value: str, option: str) -> tuple[str, Path]:
    if "=" not in value:
        raise argparse.ArgumentTypeError(f"{option} must be LABEL=PATH")
    label, raw_path = value.split("=", 1)
    if not label or not raw_path:
        raise argparse.ArgumentTypeError(f"{option} must be LABEL=PATH")
    return label, Path(raw_path)


def _parse_merge_run(value: str) -> tuple[str, Path]:
    return _parse_label_path(value, "--merge-run")


def _parse_device_log(value: str) -> tuple[str, Path]:
    return _parse_label_path(value, "--device-log")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze sanitized cgss-relive runtime evidence and compare profile runs"
    )
    parser.add_argument("runs", nargs="*", type=_parse_run, metavar="[LABEL=]EVENTS.jsonl")
    parser.add_argument(
        "--merge-run",
        action="append",
        type=_parse_merge_run,
        default=[],
        metavar="LABEL=EVENTS.jsonl",
        help="repeat with the same LABEL to merge control/resource logs by numeric time",
    )
    parser.add_argument(
        "--device-log",
        action="append",
        type=_parse_device_log,
        default=[],
        metavar="LABEL=DEVICE.jsonl",
        help="attach strict sanitized device-logcat evidence to an existing run label",
    )
    parser.add_argument("-o", "--output", type=Path, help="optional JSON report path")
    args = parser.parse_args()

    loaded: list[tuple[str, list[dict[str, Any]]]] = []
    device_by_label: dict[str, list[dict[str, Any]]] = {}
    try:
        labels: set[str] = set()
        for label, path in args.runs:
            if label in labels:
                raise UnsafeEventLog(f"duplicate run label: {label}")
            labels.add(label)
            loaded.append((label, load_events(path)))

        merge_paths: dict[str, list[Path]] = {}
        for label, path in args.merge_run:
            if label in labels:
                raise UnsafeEventLog(f"run label used by both positional and --merge-run: {label}")
            merge_paths.setdefault(label, []).append(path)
        for label, paths in merge_paths.items():
            streams = [load_events(path) for path in paths]
            loaded.append((label, merge_event_streams(streams)))
            labels.add(label)

        if not loaded:
            raise UnsafeEventLog("at least one run or --merge-run is required")

        device_paths: dict[str, list[Path]] = {}
        for label, path in args.device_log:
            if label not in labels:
                raise UnsafeEventLog(f"--device-log label has no matching run: {label}")
            device_paths.setdefault(label, []).append(path)
        for label, paths in device_paths.items():
            device_by_label[label] = merge_device_streams(
                [load_device_events(path) for path in paths]
            )
    except UnsafeEventLog as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    run_reports: dict[str, Any] = {}
    for label, events in loaded:
        run_report = analyze_events(events)
        if label in device_by_label:
            run_report["device_diagnostics"] = analyze_device_events(device_by_label[label])
        run_reports[label] = run_report

    report = {
        "schema": 4,
        "final_resource_version": FINAL_RESOURCE_VERSION,
        "runs": run_reports,
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
