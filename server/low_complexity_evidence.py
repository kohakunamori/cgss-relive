"""Read-only index for sanitized low-complexity response evidence.

The index accepts both frozen C22 and the newer C25 catalog.  C25 overlays five
additional exact recursive-helper object proofs onto C22; neither generation
contains parser-local empty-value proof or untouched-client acceptance.

Only compact diagnostic metadata is exposed.  Parser field lists and response
values are deliberately excluded, and shape proof remains separate from
empty-value/client acceptance proof.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

EXPECTED_ROUTE_COUNT = 76
EXPECTED_SHAPE_COUNTS_BY_GENERATION = {
    "C22": {
        "countable-collection-ambiguous": 2,
        "multi-field": 19,
        "opaque:json": 10,
        "proven-object": 44,
        "proven-scalar:int": 1,
    },
    "C25": {
        "countable-collection-ambiguous": 2,
        "multi-field": 19,
        "opaque:json": 5,
        "proven-object": 49,
        "proven-scalar:int": 1,
    },
}


@dataclass(frozen=True)
class LowComplexityRouteEvidence:
    route: str
    endpoint_id: int | None
    effective_shape: str
    effective_shape_source: str
    empty_value_status: str
    consumer_resolution: str
    next_action: str

    def safe_summary(self) -> dict[str, Any]:
        return {
            "route": self.route,
            "endpoint_id": self.endpoint_id,
            "effective_shape": self.effective_shape,
            "effective_shape_source": self.effective_shape_source,
            "empty_value_status": self.empty_value_status,
            "consumer_resolution": self.consumer_resolution,
            "next_action": self.next_action,
        }


class LowComplexityEvidenceIndex:
    def __init__(self, path: Path, *, enforce_final_counts: bool = True):
        self.path = Path(path)
        self._by_route: dict[str, LowComplexityRouteEvidence] = {}
        self.generation = "synthetic"
        self._load(enforce_final_counts=enforce_final_counts)

    @staticmethod
    def _normalize_route(route: str) -> str:
        value = "/" + str(route).split("?", 1)[0].lstrip("/")
        if value == "/":
            raise ValueError("low-complexity route cannot be empty")
        return value

    @staticmethod
    def _generation(raw: dict[str, Any]) -> str:
        # Frozen C22 predates an explicit generation field.  C25 adds one.
        value = raw.get("generation")
        if value is None:
            return "C22"
        if value == "C25":
            return "C25"
        raise ValueError(f"unsupported low-complexity evidence generation: {value!r}")

    def _load(self, *, enforce_final_counts: bool) -> None:
        if not self.path.is_file():
            raise FileNotFoundError(f"low-complexity evidence catalog is missing: {self.path}")
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw.get("schema") != 1:
            raise ValueError("low-complexity evidence catalog must contain schema=1")
        self.generation = self._generation(raw) if enforce_final_counts else str(raw.get("generation") or "synthetic")
        rows = raw.get("routes")
        if not isinstance(rows, list):
            raise ValueError("low-complexity evidence catalog routes must be a list")
        by_route: dict[str, LowComplexityRouteEvidence] = {}
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("malformed low-complexity route record")
            route = self._normalize_route(str(row.get("route") or ""))
            if route in by_route:
                raise ValueError(f"duplicate low-complexity route: {route}")
            endpoint_id = row.get("endpoint_id")
            if endpoint_id is not None and (not isinstance(endpoint_id, int) or endpoint_id <= 0):
                raise ValueError(f"invalid low-complexity endpoint id for {route}")
            values = {
                key: row.get(key)
                for key in (
                    "effective_shape",
                    "effective_shape_source",
                    "empty_value_status",
                    "consumer_resolution",
                    "next_action",
                )
            }
            if any(not isinstance(value, str) or not value for value in values.values()):
                raise ValueError(f"malformed low-complexity diagnostic fields for {route}")
            if row.get("static_evidence_only") is not True:
                raise ValueError(f"low-complexity route is not marked static-only: {route}")
            if row.get("untouched_client_acceptance") is not False:
                raise ValueError(f"low-complexity route unexpectedly claims client acceptance: {route}")
            by_route[route] = LowComplexityRouteEvidence(
                route=route,
                endpoint_id=endpoint_id,
                effective_shape=values["effective_shape"],
                effective_shape_source=values["effective_shape_source"],
                empty_value_status=values["empty_value_status"],
                consumer_resolution=values["consumer_resolution"],
                next_action=values["next_action"],
            )
        self._by_route = by_route

        if enforce_final_counts:
            expected_shapes = EXPECTED_SHAPE_COUNTS_BY_GENERATION[self.generation]
            if len(by_route) != EXPECTED_ROUTE_COUNT or raw.get("route_count") != EXPECTED_ROUTE_COUNT:
                raise ValueError(
                    f"{self.generation} route count mismatch: {len(by_route)} != {EXPECTED_ROUTE_COUNT}"
                )
            if raw.get("effective_shape_counts") != expected_shapes:
                raise ValueError(
                    f"{self.generation} effective shape counts do not match frozen final artifact"
                )
            if raw.get("parser_local_empty_value_proven_route_count") != 0:
                raise ValueError(
                    f"{self.generation} unexpectedly contains parser-local empty-value proof"
                )
            if raw.get("untouched_client_accepted_route_count") != 0:
                raise ValueError(
                    f"{self.generation} unexpectedly claims untouched-client acceptance"
                )

    @property
    def route_count(self) -> int:
        return len(self._by_route)

    @property
    def routes(self) -> tuple[str, ...]:
        return tuple(sorted(self._by_route))

    def route(self, route: str) -> LowComplexityRouteEvidence | None:
        return self._by_route.get(self._normalize_route(route))

    def safe_route_summary(self, route: str) -> dict[str, Any] | None:
        value = self.route(route)
        if value is None:
            return None
        summary = value.safe_summary()
        summary["evidence_generation"] = self.generation
        return summary

    @property
    def by_route(self) -> Mapping[str, LowComplexityRouteEvidence]:
        return dict(self._by_route)
