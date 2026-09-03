#!/usr/bin/env python3
"""Turn a schema-4 sanitized runtime report into a shareable triage summary.

The input must be produced by ``scripts/analyze-runtime-events.py``. This helper
intentionally emits only a small allow-listed summary instead of copying the
source report wholesale, so it cannot accidentally turn arbitrary JSON into a
shareable artifact.

Triage is evidence classification, not client-state inference. In particular,
reaching ``/load/index`` never proves that Home rendered; visible Home remains a
real-device observation gate.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping

SOURCE_SCHEMA = 4
TRIAGE_SCHEMA = 1
FINAL_RESOURCE_VERSION = "10133800"

_ALLOWED_PHASES = {
    "no_http_request",
    "http_reached",
    "load_check_reached",
    "resource_version_214_responded",
    "old_resource_direct_success_responded",
    "final_version_load_check_observed",
    "final_version_load_check_responded",
    "resource_plane_observed",
    "resource_plane_served",
    "load_index_reached",
    "post_load_index_observed",
}


class UnsafeRuntimeReport(ValueError):
    """Raised when the source is not the expected sanitized analyzer report."""


def _require_mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise UnsafeRuntimeReport(f"{field} must be an object")
    return value


def _require_bool(mapping: Mapping[str, Any], key: str, field: str) -> bool:
    value = mapping.get(key)
    if not isinstance(value, bool):
        raise UnsafeRuntimeReport(f"{field}.{key} must be a boolean")
    return value


def _optional_failure(value: Any, field: str) -> dict[str, Any] | None:
    if value is None:
        return None
    mapping = _require_mapping(value, field)
    route = mapping.get("route")
    status = mapping.get("status")
    event_index = mapping.get("event_index")
    if not isinstance(route, str) or not isinstance(status, int) or not isinstance(event_index, int):
        raise UnsafeRuntimeReport(f"{field} must contain route/status/event_index")
    error = mapping.get("error")
    if error is not None and not isinstance(error, str):
        raise UnsafeRuntimeReport(f"{field}.error must be a string")
    return {
        "event_index": event_index,
        "route": route,
        "status": status,
        **({"error": error} if error is not None else {}),
    }


def _device_summary(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    mapping = _require_mapping(value, "device_diagnostics")
    events = mapping.get("events")
    if not isinstance(events, int) or events < 0:
        raise UnsafeRuntimeReport("device_diagnostics.events must be a non-negative integer")
    first_failure = mapping.get("first_failure")
    safe_first_failure = None
    if first_failure is not None:
        failure = _require_mapping(first_failure, "device_diagnostics.first_failure")
        category = failure.get("category")
        severity = failure.get("severity")
        if not isinstance(category, str) or not isinstance(severity, str):
            raise UnsafeRuntimeReport(
                "device_diagnostics.first_failure must contain category/severity"
            )
        safe_first_failure = {"category": category, "severity": severity}

    return {
        "events": events,
        "first_failure": safe_first_failure,
        "has_tls_error": _require_bool(mapping, "has_tls_error", "device_diagnostics"),
        "has_process_crash": _require_bool(
            mapping, "has_process_crash", "device_diagnostics"
        ),
        "has_anr": _require_bool(mapping, "has_anr", "device_diagnostics"),
        "has_network_error": _require_bool(
            mapping, "has_network_error", "device_diagnostics"
        ),
    }


def _validate_sequence(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise UnsafeRuntimeReport("sequence must be a list")
    result: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        mapping = _require_mapping(item, f"sequence[{index}]")
        route = mapping.get("route")
        status = mapping.get("status")
        if not isinstance(route, str) or not isinstance(status, int):
            raise UnsafeRuntimeReport(f"sequence[{index}] must contain route/status")
        result.append({"route": route, "status": status})
    return result


def _validate_run(value: Any, label: str) -> dict[str, Any]:
    run = _require_mapping(value, f"runs.{label}")
    phase = run.get("phase")
    if phase not in _ALLOWED_PHASES:
        raise UnsafeRuntimeReport(f"runs.{label}.phase is unsupported")
    events = run.get("events")
    if not isinstance(events, int) or events < 0:
        raise UnsafeRuntimeReport(f"runs.{label}.events must be a non-negative integer")

    reached_raw = _require_mapping(run.get("reached"), f"runs.{label}.reached")
    reached = {
        key: _require_bool(reached_raw, key, f"runs.{label}.reached")
        for key in ("load_check", "load_title", "resource_plane", "resource_manifest", "load_index")
    }

    negotiation_raw = _require_mapping(
        run.get("resource_negotiation"), f"runs.{label}.resource_negotiation"
    )
    negotiation = {
        key: _require_bool(
            negotiation_raw, key, f"runs.{label}.resource_negotiation"
        )
        for key in (
            "server_returned_214",
            "observed_resource_request_after_214",
            "observed_successful_resource_response_after_214",
            "server_returned_direct_success_with_required_res_ver",
            "observed_followup_request_after_direct_success",
            "server_returned_success_for_10133800",
            "observed_followup_request_after_10133800_success",
        )
    }

    resource_raw = _require_mapping(run.get("resource_plane"), f"runs.{label}.resource_plane")
    routes = resource_raw.get("routes")
    if not isinstance(routes, list) or any(not isinstance(route, str) for route in routes):
        raise UnsafeRuntimeReport(f"runs.{label}.resource_plane.routes must be strings")

    return {
        "phase": phase,
        "events": events,
        "reached": reached,
        "resource_negotiation": negotiation,
        "resource_routes": list(routes),
        "first_failure": _optional_failure(run.get("first_failure"), f"runs.{label}.first_failure"),
        "device": _device_summary(run.get("device_diagnostics")),
        "sequence": _validate_sequence(run.get("sequence")),
    }


def _device_failure_category(device: Mapping[str, Any] | None) -> str | None:
    if not device:
        return None
    failure = device.get("first_failure")
    if isinstance(failure, Mapping) and isinstance(failure.get("category"), str):
        return str(failure["category"])
    return None


def classify_run(run: Mapping[str, Any]) -> dict[str, Any]:
    """Classify the next runtime gate using only sanitized evidence."""
    phase = str(run["phase"])
    reached = _require_mapping(run["reached"], "reached")
    negotiation = _require_mapping(run["resource_negotiation"], "resource_negotiation")
    device = run.get("device")
    if device is not None:
        device = _require_mapping(device, "device")
    first_failure = run.get("first_failure")
    if first_failure is not None:
        first_failure = _require_mapping(first_failure, "first_failure")
    sequence = run.get("sequence")
    if not isinstance(sequence, list):
        raise UnsafeRuntimeReport("sequence must be a list")

    index_positions = [
        index
        for index, item in enumerate(sequence)
        if isinstance(item, Mapping) and item.get("route") == "/load/index"
    ]
    last_load_index = index_positions[-1] if index_positions else None

    def result(classification: str, next_gate: str, reason: str) -> dict[str, Any]:
        return {
            "classification": classification,
            "next_gate": next_gate,
            "reason": reason,
            "server_phase": phase,
            "first_server_failure": (
                {
                    "route": str(first_failure["route"]),
                    "status": int(first_failure["status"]),
                    **(
                        {"error": str(first_failure["error"])}
                        if "error" in first_failure
                        else {}
                    ),
                }
                if first_failure is not None
                else None
            ),
            "first_device_failure_category": _device_failure_category(device),
            "visible_home_proven": False,
        }

    # A failing /load/index response is a server contract failure, not a visual gate.
    if first_failure is not None and first_failure.get("route") == "/load/index":
        return result(
            "load_index_response_failure",
            "fix_load_index_response",
            "The client reached /load/index but the sanitized server trace records it as the first failing response.",
        )

    # Once /load/index succeeded, only evidence after that point should decide the
    # next server-side gate. Earlier recoverable failures must not override progress.
    if bool(reached.get("load_index")) and last_load_index is not None:
        if (
            first_failure is not None
            and isinstance(first_failure.get("event_index"), int)
            and int(first_failure["event_index"]) > last_load_index
        ):
            return result(
                "post_load_index_server_gap",
                "implement_first_post_load_index_route",
                "A later server request failed after /load/index; this is the first observable post-index compatibility gap.",
            )
        if device and (bool(device.get("has_process_crash")) or bool(device.get("has_anr"))):
            return result(
                "client_failure_after_load_index",
                "inspect_private_device_failure_after_load_index",
                "The server observed /load/index and the sanitized device diagnostics later contain a crash or ANR signal.",
            )
        if phase == "post_load_index_observed":
            return result(
                "post_load_index_observed_visual_gate",
                "confirm_visible_home",
                "The client made a later request after /load/index; HTTP evidence still cannot prove that Home rendered.",
            )
        return result(
            "load_index_reached_visual_gate",
            "confirm_visible_home_or_capture_next_action",
            "The client reached /load/index, but visible Home requires direct original-client observation or a later observable action.",
        )

    # If the resource resolver admits an unresolved family before /load/index,
    # classify it even when the synthetic event itself was not an HTTP >=400.
    if "@resource/unresolved" in run.get("resource_routes", []):
        return result(
            "resource_route_unresolved",
            "identify_missing_resource_url_family_privately",
            "A resource request reached the backend but did not map to a reconstructed sanitized resource family.",
        )

    if first_failure is not None:
        route = str(first_failure.get("route"))
        if route.startswith("@resource/"):
            return result(
                "resource_response_failure",
                "fix_first_failing_resource_response",
                "A resource-plane response failed before /load/index.",
            )
        return result(
            "control_plane_server_failure",
            "fix_first_failing_control_route",
            "A control-plane HTTP response failed before the client reached /load/index.",
        )

    if phase == "no_http_request":
        if device and bool(device.get("has_tls_error")):
            return result(
                "pre_http_tls_failure",
                "fix_device_tls_trust_or_route",
                "No local HTTP request was observed and sanitized device diagnostics contain a TLS failure.",
            )
        category = _device_failure_category(device)
        if category == "dns_error":
            return result(
                "pre_http_dns_failure",
                "fix_device_hosts_mapping",
                "No local HTTP request was observed and the first classified device failure is DNS resolution.",
            )
        if category == "connection_refused":
            return result(
                "pre_http_tunnel_failure",
                "verify_adb_reverse_and_tls_mux",
                "No local HTTP request was observed and the device saw a refused connection.",
            )
        if device and bool(device.get("has_network_error")):
            return result(
                "pre_http_transport_failure",
                "verify_device_routing_tunnel_and_host_stack",
                "No local HTTP request was observed and sanitized device diagnostics contain a network failure.",
            )
        if device and (bool(device.get("has_process_crash")) or bool(device.get("has_anr"))):
            return result(
                "client_failure_before_http",
                "inspect_private_device_failure_before_http",
                "The client produced a crash or ANR signal before any local HTTP request was observed.",
            )
        if category == "process_exit":
            return result(
                "client_exit_before_http",
                "inspect_private_device_exit_before_http",
                "The target process exited before any local HTTP request was observed.",
            )
        return result(
            "no_http_no_classified_device_signal",
            "verify_device_preflight_and_capture",
            "No local HTTP request was observed and the sanitized device diagnostics do not identify a classified failure.",
        )

    if bool(negotiation.get("server_returned_214")) and not bool(reached.get("resource_plane")):
        if device and (bool(device.get("has_process_crash")) or bool(device.get("has_anr"))):
            return result(
                "client_failure_after_214_before_resource",
                "inspect_savedata_then_private_device_failure",
                "The server returned 214, no resource request followed, and the device later reported a crash or ANR.",
            )
        if device and (bool(device.get("has_tls_error")) or bool(device.get("has_network_error"))):
            return result(
                "transport_failure_after_214_before_resource",
                "verify_storage_hostname_tls_and_tunnel",
                "The server returned 214, no resource request followed, and device diagnostics contain a transport/TLS failure.",
            )
        return result(
            "stalled_after_214_before_resource",
            "verify_savedata_res_ver_and_storage_route",
            "The 214 response was observed but no later resource-plane request was seen; absence of a second /load/check is not itself a failure.",
        )

    if bool(reached.get("resource_plane")) and not bool(reached.get("load_index")):
        if device and (bool(device.get("has_process_crash")) or bool(device.get("has_anr"))):
            return result(
                "client_failure_during_resource_initialization",
                "inspect_private_device_failure_during_resources",
                "Resource traffic was observed but the client crashed or ANRed before /load/index.",
            )
        if device and bool(device.get("has_network_error")):
            return result(
                "transport_failure_during_resource_initialization",
                "fix_resource_transport_before_load_index",
                "Resource traffic was observed but device diagnostics contain a network failure before /load/index.",
            )
        if bool(negotiation.get("observed_successful_resource_response_after_214")) or phase == "resource_plane_served":
            return result(
                "stalled_after_resource_plane",
                "capture_next_resource_or_load_index_action",
                "At least one resource response was served, but /load/index has not yet been observed.",
            )
        return result(
            "resource_plane_observed_not_served",
            "fix_resource_response_before_load_index",
            "The client reached the resource backend, but no successful sanitized resource response is proven.",
        )

    if bool(negotiation.get("server_returned_direct_success_with_required_res_ver")):
        return result(
            "stalled_after_direct_success",
            "compare_native_and_direct_clean_state",
            "The diagnostic old-version direct-success response was returned without reaching a later mainline gate.",
        )

    if bool(negotiation.get("server_returned_success_for_10133800")):
        return result(
            "stalled_after_final_load_check",
            "verify_manifest_initialization_after_final_check",
            "The final resource-version /load/check succeeded but no resource-plane or /load/index progress followed.",
        )

    if bool(reached.get("load_check")):
        return result(
            "load_check_reached_unclassified_progress",
            "verify_load_check_response_semantics",
            "The local backend saw /load/check, but the sanitized evidence does not yet prove a recognized 214/final-success continuation.",
        )

    return result(
        "http_reached_before_bootstrap_gate",
        "capture_until_load_check_or_first_failure",
        "Local HTTP traffic exists, but /load/check has not yet been observed and no failing response is recorded.",
    )


def build_triage_report(source: Any) -> dict[str, Any]:
    root = _require_mapping(source, "report")
    if root.get("schema") != SOURCE_SCHEMA:
        raise UnsafeRuntimeReport(f"expected analyzer schema {SOURCE_SCHEMA}")
    if str(root.get("final_resource_version")) != FINAL_RESOURCE_VERSION:
        raise UnsafeRuntimeReport("unexpected final_resource_version")
    runs = _require_mapping(root.get("runs"), "runs")
    if not runs:
        raise UnsafeRuntimeReport("runs must not be empty")

    triaged_runs: dict[str, Any] = {}
    for label, raw_run in runs.items():
        if not isinstance(label, str) or not label:
            raise UnsafeRuntimeReport("run labels must be non-empty strings")
        validated = _validate_run(raw_run, label)
        triaged_runs[label] = classify_run(validated)

    return {
        "schema": TRIAGE_SCHEMA,
        "source_report_schema": SOURCE_SCHEMA,
        "final_resource_version": FINAL_RESOURCE_VERSION,
        "visible_home_requires_real_device_observation": True,
        "runs": triaged_runs,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Classify the next CGSS real-device runtime gate from a sanitized analyzer report"
    )
    parser.add_argument("report", type=Path, help="schema-4 report from analyze-runtime-events.py")
    parser.add_argument("-o", "--output", type=Path, help="optional triage JSON output")
    args = parser.parse_args()

    try:
        source = json.loads(args.report.read_text(encoding="utf-8"))
        report = build_triage_report(source)
    except (OSError, json.JSONDecodeError, UnsafeRuntimeReport) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
