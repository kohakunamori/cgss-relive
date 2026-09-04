"""Runtime-safe index for sanitized C13 effective base-parser overlays.

C13 supplements C9 concrete endpoint fields with base parser surfaces reached by
exact direct-BL evidence or exact inheritance/no-override evidence.  The overlay
is provenance, not a response-value source.  Runtime events expose aggregate
counts only; field names and caller details remain in the offline catalog.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .semantic_contracts import SemanticContractIndex

EXPECTED_RELATION_COUNT = 438
EXPECTED_ENDPOINT_COUNT = 389
EXPECTED_FIELD_LINK_COUNT = 1871
EXPECTED_RESIDUAL_METHOD_COUNT = 1


@dataclass(frozen=True)
class ParserOverlay:
    endpoint_id: int
    route: str
    base_task: str
    base_parser_method: str
    base_parser_rva: int
    field_count: int
    required_field_count: int
    unknown_field_count: int
    provenance_kinds: tuple[str, ...]


class EffectiveParserOverlayIndex:
    def __init__(
        self,
        path: Path,
        *,
        semantic_index: SemanticContractIndex,
        enforce_final_counts: bool = True,
    ) -> None:
        self.path = Path(path)
        self._by_endpoint: dict[int, tuple[ParserOverlay, ...]] = {}
        self._load(semantic_index=semantic_index, enforce_final_counts=enforce_final_counts)

    def _load(self, *, semantic_index: SemanticContractIndex, enforce_final_counts: bool) -> None:
        doc = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(doc, dict) or doc.get("schema") != 1:
            raise ValueError("C13 parser overlay root must contain schema=1")
        raw = doc.get("overlays")
        if not isinstance(raw, list):
            raise ValueError("C13 parser overlay root must contain an overlays list")

        by_endpoint: dict[int, list[ParserOverlay]] = defaultdict(list)
        relation_count = 0
        field_links = 0
        seen: set[tuple[int, int]] = set()
        for row in raw:
            if not isinstance(row, dict):
                raise ValueError("C13 overlay entry must be an object")
            endpoint = row.get("endpoint")
            fields = row.get("fields")
            provenance = row.get("provenance")
            if not isinstance(endpoint, dict) or not isinstance(fields, list) or not isinstance(provenance, list):
                raise ValueError("C13 overlay entry has malformed endpoint/fields/provenance")
            endpoint_id = endpoint.get("endpoint_id")
            route = endpoint.get("route")
            base_task = row.get("base_task")
            method = row.get("base_parser_method")
            rva = row.get("base_parser_rva")
            if not isinstance(endpoint_id, int) or endpoint_id <= 0:
                raise ValueError("C13 overlay endpoint_id must be positive")
            if not isinstance(route, str) or not route.startswith("/"):
                raise ValueError("C13 overlay route must be an HTTP path")
            if not isinstance(base_task, str) or not isinstance(method, str) or not isinstance(rva, int):
                raise ValueError("C13 overlay base parser identity is malformed")
            key = (endpoint_id, rva)
            if key in seen:
                raise ValueError(f"duplicate C13 endpoint/base-parser overlay: {key}")
            seen.add(key)

            c9_endpoint = semantic_index.endpoint(endpoint_id)
            if c9_endpoint.route != route:
                raise ValueError(
                    f"C13/C9 endpoint route mismatch for {endpoint_id}: {route} != {c9_endpoint.route}"
                )

            required = 0
            unknown = 0
            for field in fields:
                if not isinstance(field, dict) or not isinstance(field.get("field"), str):
                    raise ValueError("C13 overlay field entry is malformed")
                kind = field.get("requiredness")
                if kind == "required-path":
                    required += 1
                if kind == "unknown-cfg":
                    unknown += 1
            kinds: set[str] = set()
            for item in provenance:
                if not isinstance(item, dict) or not isinstance(item.get("kind"), str):
                    raise ValueError("C13 overlay provenance entry is malformed")
                if item["kind"] not in {"direct-BL", "inherited-no-override"}:
                    raise ValueError(f"unsupported C13 provenance kind: {item['kind']}")
                kinds.add(item["kind"])
            if not kinds:
                raise ValueError("C13 overlay must retain at least one provenance kind")

            overlay = ParserOverlay(
                endpoint_id=endpoint_id,
                route=route,
                base_task=base_task,
                base_parser_method=method,
                base_parser_rva=rva,
                field_count=len(fields),
                required_field_count=required,
                unknown_field_count=unknown,
                provenance_kinds=tuple(sorted(kinds)),
            )
            by_endpoint[endpoint_id].append(overlay)
            relation_count += 1
            field_links += len(fields)

        self._by_endpoint = {
            endpoint_id: tuple(sorted(items, key=lambda item: (item.base_parser_rva, item.base_parser_method)))
            for endpoint_id, items in by_endpoint.items()
        }

        if enforce_final_counts:
            if relation_count != EXPECTED_RELATION_COUNT:
                raise ValueError(f"C13 overlay relation count mismatch: {relation_count}")
            if len(self._by_endpoint) != EXPECTED_ENDPOINT_COUNT:
                raise ValueError(f"C13 overlay endpoint count mismatch: {len(self._by_endpoint)}")
            if field_links != EXPECTED_FIELD_LINK_COUNT:
                raise ValueError(f"C13 overlay field-link count mismatch: {field_links}")
            if int(doc.get("residual_unmapped_method_count", -1)) != EXPECTED_RESIDUAL_METHOD_COUNT:
                raise ValueError("C13 residual unmapped method count mismatch")

    @property
    def endpoint_count(self) -> int:
        return len(self._by_endpoint)

    @property
    def relation_count(self) -> int:
        return sum(len(items) for items in self._by_endpoint.values())

    @property
    def field_link_count(self) -> int:
        return sum(item.field_count for items in self._by_endpoint.values() for item in items)

    def endpoint_overlays(self, endpoint_id: int) -> tuple[ParserOverlay, ...]:
        return self._by_endpoint.get(int(endpoint_id), ())

    def safe_endpoint_summary(self, endpoint_id: int) -> dict[str, Any]:
        overlays = self.endpoint_overlays(endpoint_id)
        provenance = Counter(
            kind for overlay in overlays for kind in overlay.provenance_kinds
        )
        return {
            "effective_base_parser_count": len(overlays),
            "effective_base_field_link_count": sum(item.field_count for item in overlays),
            "effective_base_required_field_link_count": sum(item.required_field_count for item in overlays),
            "effective_base_unknown_field_link_count": sum(item.unknown_field_count for item in overlays),
            "effective_base_provenance": sorted(provenance),
        }
