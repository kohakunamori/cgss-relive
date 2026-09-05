"""Wire-independent preservation-domain value types.

These types deliberately avoid CGSS response-field names.  They describe semantic
state changes that compatibility adapters can project into endpoint-specific DTOs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping


class EvidenceStatus(str, Enum):
    PROVEN_STATIC = "proven-static"
    PROVEN_RUNTIME = "proven-runtime"
    MASTER_DATA_DERIVED = "master-data-derived"
    HISTORICAL_REFERENCE = "historical-reference"
    CANDIDATE = "candidate"
    UNRESOLVED = "unresolved"


class EvidenceKind(str, Enum):
    EXACT = "exact"
    INFERRED = "inferred"
    POLICY = "policy"


@dataclass(frozen=True)
class Evidence:
    status: EvidenceStatus
    kind: EvidenceKind
    source: str | None = None
    note: str | None = None


@dataclass(frozen=True)
class Reward:
    """A normalized positive grant emitted by a domain operation."""

    kind: str
    quantity: int
    master_ref_id: int | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.kind:
            raise ValueError("reward kind must be non-empty")
        if self.quantity <= 0:
            raise ValueError("reward quantity must be positive")
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))


@dataclass(frozen=True)
class ResourceChange:
    """Change to a normalized wallet/resource counter."""

    resource_kind: str
    delta: int
    resulting_amount: int | None = None

    def __post_init__(self) -> None:
        if not self.resource_kind:
            raise ValueError("resource kind must be non-empty")
        if self.delta == 0:
            raise ValueError("resource delta must be non-zero")
        if self.resulting_amount is not None and self.resulting_amount < 0:
            raise ValueError("resulting resource amount must be non-negative")


class ChangeOperation(str, Enum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"


@dataclass(frozen=True)
class EntityChange:
    """Semantic change to a domain entity, independent of response DTO layout."""

    category: str
    entity_id: str
    operation: ChangeOperation
    values: Mapping[str, Any] = field(default_factory=dict)
    evidence: Evidence | None = None

    def __post_init__(self) -> None:
        if not self.category:
            raise ValueError("entity category must be non-empty")
        if not self.entity_id:
            raise ValueError("entity id must be non-empty")
        object.__setattr__(self, "values", MappingProxyType(dict(self.values)))


@dataclass(frozen=True)
class ChangeSet:
    """Normalized result of one preservation-domain command.

    Endpoint adapters consume this object and decide which client-specific update
    structures need to be emitted.  It intentionally does not encode a CGSS route.
    """

    profile_changed: bool = False
    resources: tuple[ResourceChange, ...] = ()
    entities: tuple[EntityChange, ...] = ()
    emitted_rewards: tuple[Reward, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "resources", tuple(self.resources))
        object.__setattr__(self, "entities", tuple(self.entities))
        object.__setattr__(self, "emitted_rewards", tuple(self.emitted_rewards))
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))

    @property
    def is_empty(self) -> bool:
        return not (
            self.profile_changed
            or self.resources
            or self.entities
            or self.emitted_rewards
            or self.metadata
        )
