"""Preservation-domain primitives for cgss-relive.

This package is intentionally independent of CGSS wire DTOs.  Route/serializer
adapters should translate between client contracts and these domain types.
"""

from .core import (
    ChangeOperation,
    ChangeSet,
    EntityChange,
    Evidence,
    EvidenceKind,
    EvidenceStatus,
    ResourceChange,
    Reward,
)
from .providers import (
    Clock,
    FixedClock,
    IdGenerator,
    RandomSource,
    SeededRandomSource,
    SequentialIdGenerator,
    SystemClock,
)

__all__ = [
    "ChangeOperation",
    "ChangeSet",
    "Clock",
    "EntityChange",
    "Evidence",
    "EvidenceKind",
    "EvidenceStatus",
    "FixedClock",
    "IdGenerator",
    "RandomSource",
    "ResourceChange",
    "Reward",
    "SeededRandomSource",
    "SequentialIdGenerator",
    "SystemClock",
]
