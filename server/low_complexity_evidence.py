"""Read-only index for the sanitized C22 low-complexity response evidence.

C22 contains static final-client parser/helper metadata only.  This module exposes
compact diagnostic summaries for runtime blocker analysis, while deliberately
excluding parser field lists and response values.  Shape proof is kept separate
from empty-value proof and untouched-client acceptance.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

EXPECTED_ROUTE_COUNT = 76
EXPECTED_SHAPE_COUNTS = {
    "countable-collection-ambiguous": 2,
    "multi-field": 19,
    "opaque:json": 10,
    "proven-object": 44,
    "proven-scalar:int": 1,
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
        self._load(enforce_final_counts=enforce_final_counts)

    @staticmethod
    def _normalize_route(route: str) -> str:
        value = "/" + str(route).split("?", 1)[0].lstrip("/")
        if value == "/":
            raise ValueError("C22 route cannot be empty")
        return value

    def _load(self, *, enforce_final_counts: bool) -> None:
        if not self.path.is_file():
            raise FileNotFoundError(f"C22 evidence catalog is missing: {self.path}")
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw.get("schema") != 1:
            raise ValueError("C22 evidence catalog must contain schema=1")
        rows = raw.get("routes")
        if not isinstance(rows, list):
            raise ValueError("C22 evidence catalog routes must be a list")
        by_route: dict[str, LowComplexityRouteEvidence] = {}
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("malformed C22 route record")
            route = self._normalize_route(str(row.get("route") or ""))
            if route in by_route:
                raise ValueError(f"duplicate C22 route: {route}")
            endpoint_id = row.get("endpoint_id")
            if endpoint_id is not None and (not isinstance(endpoint_id, int) or endpoint_id <= 0):
                raise ValueError(f"invalid C22 endpoint id for {route}")
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
                raise ValueError(f"malformed C22 diagnostic fields for {route}")
            if row.get("static_evidence_only") is not True:
                raise ValueError(f"C22 route is not marked static-only: {route}")
            if row.get("untouched_client_acceptance") is not False:
                raise ValueError(f"C22 route unexpectedly claims client acceptance: {route}")
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
            if len(by_route) != EXPECTED_ROUTE_COUNT or raw.get("route_count") != EXPECTED_ROUTE_COUNT:
                raise ValueError(f"C22 route count mismatch: {len(by_route)} != {EXPECTED_ROUTE_COUNT}")
            if raw.get("effective_shape_counts") != EXPECTED_SHAPE_COUNTS:
                raise ValueError("C22 effective shape counts do not match frozen final artifact")
            if raw.get("parser_local_empty_value_proven_route_count") != 0:
                raise ValueError("C22 unexpectedly contains parser-local empty-value proof")
            if raw.get("untouched_client_accepted_route_count") != 0:
                raise ValueError("C22 unexpectedly claims untouched-client acceptance")

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
        return value.safe_summary() if value is not None else None

    @property
    def by_route(self) -> Mapping[str, LowComplexityRouteEvidence]:
        return dict(self._by_route)
