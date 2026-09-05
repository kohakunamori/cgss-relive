"""Runtime-safe reader for the sanitized final-client C9 semantic database.

The C9 SQLite artifact contains reconstructed endpoint/field/state semantics only;
it does not contain APK bytes, native code, resource bodies or account data.  This
module deliberately treats the database as read-only evidence.  It can tell the
HTTP layer that a route is known and describe its candidate endpoint records, but
it never invents a response body from flat parser-field evidence.

A route is not a unique endpoint identity in the final client.  The index therefore
preserves all endpoint IDs for a path and exposes duplicate-route ambiguity instead
of collapsing records by ``(route, enum)`` or path.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

EXPECTED_ENDPOINT_COUNT = 538
EXPECTED_UNIQUE_ROUTE_COUNT = 526
EXPECTED_DUPLICATE_ROUTE_COUNT = 9


@dataclass(frozen=True)
class ResponseFieldContract:
    task: str
    method: str | None
    field: str
    requiredness: str | None
    value_types: tuple[str, ...]


@dataclass(frozen=True)
class EndpointContract:
    endpoint_id: int
    route: str
    enum: str | None
    status: str | None
    group: str | None
    api_key: int | None
    request_field_count: int
    response_fields: tuple[ResponseFieldContract, ...]
    exact_state_mutation_count: int
    inferred_subsystems: tuple[str, ...]

    @property
    def response_field_count(self) -> int:
        return len(self.response_fields)

    @property
    def required_response_fields(self) -> tuple[ResponseFieldContract, ...]:
        return tuple(field for field in self.response_fields if field.requiredness == "required-path")

    @property
    def unknown_response_fields(self) -> tuple[ResponseFieldContract, ...]:
        return tuple(field for field in self.response_fields if field.requiredness == "unknown-cfg")

    def safe_event_summary(self) -> dict[str, Any]:
        """Return only public/sanitized contract metadata for runtime logs."""
        return {
            "endpoint_id": self.endpoint_id,
            "group": self.group,
            "key": self.api_key,
            "enum": self.enum,
            "status": self.status,
            "request_field_count": self.request_field_count,
            "response_field_count": self.response_field_count,
            "required_response_field_count": len(self.required_response_fields),
            "unknown_response_field_count": len(self.unknown_response_fields),
            "exact_state_mutation_count": self.exact_state_mutation_count,
        }


class SemanticContractIndex:
    """In-memory route index loaded from a validated C9 SQLite artifact."""

    def __init__(self, path: Path, *, enforce_final_counts: bool = True):
        self.path = Path(path)
        self._by_route: dict[str, tuple[EndpointContract, ...]] = {}
        self._by_id: dict[int, EndpointContract] = {}
        self._load(enforce_final_counts=enforce_final_counts)

    @staticmethod
    def _normalize_route(route: str) -> str:
        value = "/" + str(route).split("?", 1)[0].lstrip("/")
        if value == "/":
            raise ValueError("semantic endpoint route cannot be empty")
        return value

    @staticmethod
    def _decode_string_list(value: str | None) -> tuple[str, ...]:
        if not value:
            return ()
        raw = json.loads(value)
        if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
            raise ValueError("semantic field value_types_json must contain a string list")
        return tuple(sorted(set(raw)))

    @staticmethod
    def _required_schema_objects(db: sqlite3.Connection) -> None:
        names = {
            row[0]
            for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type IN ('table','view')"
            )
        }
        required = {
            "endpoints",
            "request_fields",
            "response_fields",
            "endpoint_state_mutations",
            "endpoint_subsystems",
            "subsystems",
            "endpoint_semantics",
        }
        missing = required - names
        if missing:
            raise ValueError(f"semantic DB is missing schema objects: {sorted(missing)}")

    def _load(self, *, enforce_final_counts: bool) -> None:
        if not self.path.is_file():
            raise FileNotFoundError(f"semantic contract DB is missing: {self.path}")
        uri = f"file:{self.path.resolve().as_posix()}?mode=ro"
        db = sqlite3.connect(uri, uri=True)
        db.row_factory = sqlite3.Row
        try:
            quick = db.execute("PRAGMA quick_check").fetchone()
            if quick is None or quick[0] != "ok":
                raise ValueError(f"semantic DB quick_check failed: {quick[0] if quick else 'no result'}")
            self._required_schema_objects(db)

            response_fields: dict[int, list[ResponseFieldContract]] = {}
            for row in db.execute(
                """
                SELECT endpoint_id,task,method,field,requiredness,value_types_json
                FROM response_fields
                WHERE endpoint_id IS NOT NULL
                ORDER BY endpoint_id,id
                """
            ):
                endpoint_id = int(row["endpoint_id"])
                response_fields.setdefault(endpoint_id, []).append(
                    ResponseFieldContract(
                        task=str(row["task"]),
                        method=str(row["method"]) if row["method"] is not None else None,
                        field=str(row["field"]),
                        requiredness=(
                            str(row["requiredness"]) if row["requiredness"] is not None else None
                        ),
                        value_types=self._decode_string_list(row["value_types_json"]),
                    )
                )

            request_counts = {
                int(row[0]): int(row[1])
                for row in db.execute(
                    "SELECT endpoint_id,COUNT(*) FROM request_fields "
                    "WHERE endpoint_id IS NOT NULL GROUP BY endpoint_id"
                )
            }
            mutation_counts = {
                int(row[0]): int(row[1])
                for row in db.execute(
                    "SELECT endpoint_id,COUNT(*) FROM endpoint_state_mutations GROUP BY endpoint_id"
                )
            }
            subsystems: dict[int, set[str]] = {}
            for row in db.execute(
                """
                SELECT es.endpoint_id,s.name
                FROM endpoint_subsystems es
                JOIN subsystems s ON s.id=es.subsystem_id
                ORDER BY es.endpoint_id,s.name
                """
            ):
                subsystems.setdefault(int(row[0]), set()).add(str(row[1]))

            by_route: dict[str, list[EndpointContract]] = {}
            by_id: dict[int, EndpointContract] = {}
            for row in db.execute(
                "SELECT id,route,enum,status,group_name,api_key FROM endpoints ORDER BY id"
            ):
                endpoint_id = int(row["id"])
                route = self._normalize_route(str(row["route"]))
                if endpoint_id in by_id:
                    raise ValueError(f"duplicate semantic endpoint id: {endpoint_id}")
                endpoint = EndpointContract(
                    endpoint_id=endpoint_id,
                    route=route,
                    enum=str(row["enum"]) if row["enum"] is not None else None,
                    status=str(row["status"]) if row["status"] is not None else None,
                    group=str(row["group_name"]) if row["group_name"] is not None else None,
                    api_key=int(row["api_key"]) if row["api_key"] is not None else None,
                    request_field_count=request_counts.get(endpoint_id, 0),
                    response_fields=tuple(response_fields.get(endpoint_id, ())),
                    exact_state_mutation_count=mutation_counts.get(endpoint_id, 0),
                    inferred_subsystems=tuple(sorted(subsystems.get(endpoint_id, set()))),
                )
                by_id[endpoint_id] = endpoint
                by_route.setdefault(route, []).append(endpoint)

            self._by_id = by_id
            self._by_route = {
                route: tuple(sorted(items, key=lambda item: item.endpoint_id))
                for route, items in by_route.items()
            }

            if enforce_final_counts:
                if len(self._by_id) != EXPECTED_ENDPOINT_COUNT:
                    raise ValueError(
                        f"semantic DB endpoint count mismatch: {len(self._by_id)} != {EXPECTED_ENDPOINT_COUNT}"
                    )
                if len(self._by_route) != EXPECTED_UNIQUE_ROUTE_COUNT:
                    raise ValueError(
                        "semantic DB unique-route count mismatch: "
                        f"{len(self._by_route)} != {EXPECTED_UNIQUE_ROUTE_COUNT}"
                    )
                if len(self.duplicate_routes) != EXPECTED_DUPLICATE_ROUTE_COUNT:
                    raise ValueError(
                        "semantic DB duplicate-route group count mismatch: "
                        f"{len(self.duplicate_routes)} != {EXPECTED_DUPLICATE_ROUTE_COUNT}"
                    )
        finally:
            db.close()

    @property
    def endpoint_count(self) -> int:
        return len(self._by_id)

    @property
    def unique_route_count(self) -> int:
        return len(self._by_route)

    @property
    def routes(self) -> tuple[str, ...]:
        return tuple(sorted(self._by_route))

    @property
    def duplicate_routes(self) -> Mapping[str, tuple[EndpointContract, ...]]:
        return {route: values for route, values in self._by_route.items() if len(values) > 1}

    def endpoint(self, endpoint_id: int) -> EndpointContract:
        try:
            return self._by_id[int(endpoint_id)]
        except KeyError as exc:
            raise KeyError(f"unknown semantic endpoint id: {endpoint_id}") from exc

    def route_candidates(self, route: str) -> tuple[EndpointContract, ...]:
        return self._by_route.get(self._normalize_route(route), ())

    def safe_route_candidates(self, route: str) -> list[dict[str, Any]]:
        return [candidate.safe_event_summary() for candidate in self.route_candidates(route)]

    def iter_endpoints(self) -> Iterable[EndpointContract]:
        for endpoint_id in sorted(self._by_id):
            yield self._by_id[endpoint_id]
