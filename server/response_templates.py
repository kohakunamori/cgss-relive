"""Local response-template injection for reconstructed non-bootstrap endpoints.

Templates are deliberately data-only and stay outside the repository when they
contain reconstructed/proprietary payload bodies.  The server supplies the common
success envelope and encryption.  A template cannot target an ambiguous HTTP path:
final 11.6.3 has several duplicate routes, and path-only HTTP dispatch cannot prove
which endpoint record the client intended.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .semantic_contracts import SemanticContractIndex

SCHEMA = 1


@dataclass(frozen=True)
class ResponseTemplate:
    route: str
    endpoint_id: int
    data: Mapping[str, Any]
    evidence: str | None = None


class ResponseTemplateStore:
    def __init__(self, templates: Mapping[str, ResponseTemplate]):
        self._templates = dict(templates)

    @staticmethod
    def _normalize_route(route: str) -> str:
        return "/" + str(route).split("?", 1)[0].lstrip("/")

    @classmethod
    def load(cls, path: Path, *, semantic_index: SemanticContractIndex) -> "ResponseTemplateStore":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw.get("schema") != SCHEMA:
            raise ValueError(f"response template root must contain schema={SCHEMA}")
        routes = raw.get("routes")
        if not isinstance(routes, dict):
            raise ValueError("response template root must contain a routes object")

        parsed: dict[str, ResponseTemplate] = {}
        for route_key, value in routes.items():
            if not isinstance(route_key, str) or not route_key:
                raise ValueError("response template route keys must be non-empty strings")
            route = cls._normalize_route(route_key)
            if route in parsed:
                raise ValueError(f"duplicate normalized response template route: {route}")
            if not isinstance(value, dict):
                raise ValueError(f"response template {route} must be an object")
            allowed = {"endpoint_id", "data", "evidence"}
            extra = set(value) - allowed
            if extra:
                raise ValueError(f"response template {route} has unsupported keys: {sorted(extra)}")
            if "endpoint_id" not in value:
                raise ValueError(f"response template {route} must declare endpoint_id")
            endpoint_id = value["endpoint_id"]
            if not isinstance(endpoint_id, int):
                raise ValueError(f"response template {route} endpoint_id must be an integer")
            data = value.get("data")
            if not isinstance(data, dict):
                raise ValueError(f"response template {route} data must be an object")
            evidence = value.get("evidence")
            if evidence is not None and not isinstance(evidence, str):
                raise ValueError(f"response template {route} evidence must be a string")

            candidates = semantic_index.route_candidates(route)
            if not candidates:
                raise ValueError(f"response template route is absent from C9 semantics: {route}")
            if len(candidates) != 1:
                ids = [candidate.endpoint_id for candidate in candidates]
                raise ValueError(
                    f"response template route {route} is ambiguous in C9 (endpoint_ids={ids}); "
                    "path-only template dispatch is forbidden"
                )
            if candidates[0].endpoint_id != endpoint_id:
                raise ValueError(
                    f"response template {route} endpoint_id mismatch: "
                    f"{endpoint_id} != {candidates[0].endpoint_id}"
                )
            parsed[route] = ResponseTemplate(
                route=route,
                endpoint_id=endpoint_id,
                data=dict(data),
                evidence=evidence,
            )
        return cls(parsed)

    @property
    def routes(self) -> tuple[str, ...]:
        return tuple(sorted(self._templates))

    def get(self, route: str) -> ResponseTemplate | None:
        return self._templates.get(self._normalize_route(route))

    def __contains__(self, route: str) -> bool:
        return self.get(route) is not None
