"""Runtime templates backed by C27 parser-local dead-value proofs.

C27 proves that the exact top-level ``data`` value returned by one final-client
parser is semantically dead after ``JsonData.get_Item(\"data\")``: every
reachable post-access path terminates at a known exit, with no call argument,
branch predicate, store/escape, return-value use, or unresolved control flow.

That proof is narrower than endpoint/business correctness.  It only means the
field must be present and its JSON value is irrelevant to this parser.  This
layer therefore chooses the deterministic minimal value ``{}`` and retains the
C27 provenance.  Untouched-client and UI acceptance remain separate evidence
levels.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .response_templates import ResponseTemplate, ResponseTemplateStore
from .semantic_contracts import SemanticContractIndex

SCHEMA = 1
EXPECTED_ROUTE = "/stream/telescope_view/send_action"
EXPECTED_ENDPOINT_ID = 414
EXPECTED_TASK = "Stage.TeleScopeSendActionTask"
EXPECTED_METHOD = "Stage.TeleScopeSendActionTask$$Parse"

EVIDENCE = (
    "C27 parser-local dead-value proof: final-client parser requires top-level data "
    "to be present, but the exact JsonData value has zero semantic sinks, zero "
    "reachable unresolved control flow, and reaches a known exit. Deterministic {} "
    "is therefore parser-locally safe; untouched-client/business acceptance remains unproven."
)


class DeadValueTemplateError(ValueError):
    pass


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DeadValueTemplateError(f"could not read C27 report: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        raise DeadValueTemplateError("C27 report must contain schema=1")
    return value


def _validate_proof(report: dict[str, Any]) -> tuple[str, int]:
    route = report.get("route")
    endpoint_id = report.get("endpoint_id")
    if not isinstance(route, str) or not route.startswith("/"):
        raise DeadValueTemplateError("C27 route is missing/invalid")
    if not isinstance(endpoint_id, int) or endpoint_id <= 0:
        raise DeadValueTemplateError("C27 endpoint_id is missing/invalid")

    if report.get("parser_data_value_class") != "dead-value":
        raise DeadValueTemplateError("C27 report does not prove a dead response value")
    if report.get("parser_local_arbitrary_json_value_safe") is not True:
        raise DeadValueTemplateError("C27 report does not prove arbitrary JSON value safety")
    if report.get("empty_object_promotion") != "parser-local-safe-if-field-present":
        raise DeadValueTemplateError("C27 report does not authorize deterministic empty-object promotion")
    if report.get("semantic_sink_count") != 0 or report.get("semantic_sinks") != []:
        raise DeadValueTemplateError("C27 dead-value proof contains a semantic sink")
    if report.get("reachable_unresolved_control_flow") != []:
        raise DeadValueTemplateError("C27 dead-value proof contains unresolved control flow")
    normal = report.get("reachable_normal_return_count")
    tails = report.get("reachable_managed_tail_exit_count")
    if not isinstance(normal, int) or not isinstance(tails, int) or normal + tails <= 0:
        raise DeadValueTemplateError("C27 proof has no known reachable exit")
    if report.get("untouched_client_acceptance") is not False:
        raise DeadValueTemplateError("C27 report unexpectedly claims untouched-client acceptance")
    if report.get("ui_visible_success") is not False:
        raise DeadValueTemplateError("C27 report unexpectedly claims UI-visible success")
    return route, endpoint_id


def load_dead_value_templates(
    path: Path,
    *,
    semantic_index: SemanticContractIndex,
    enforce_final_identity: bool = True,
) -> ResponseTemplateStore:
    report = _load(path)
    route, endpoint_id = _validate_proof(report)

    if enforce_final_identity:
        identity = (
            route,
            endpoint_id,
            report.get("task"),
            report.get("method"),
        )
        expected = (
            EXPECTED_ROUTE,
            EXPECTED_ENDPOINT_ID,
            EXPECTED_TASK,
            EXPECTED_METHOD,
        )
        if identity != expected:
            raise DeadValueTemplateError(
                f"C27 final-client identity mismatch: {identity!r} != {expected!r}"
            )

    candidates = semantic_index.route_candidates(route)
    if len(candidates) != 1:
        raise DeadValueTemplateError(f"C27 route is not unique in C9: {route}")
    if candidates[0].endpoint_id != endpoint_id:
        raise DeadValueTemplateError(
            f"C27/C9 endpoint identity mismatch for {route}: "
            f"{endpoint_id} != {candidates[0].endpoint_id}"
        )

    return ResponseTemplateStore(
        {
            route: ResponseTemplate(
                route=route,
                endpoint_id=endpoint_id,
                data={},
                evidence=EVIDENCE,
            )
        }
    )
