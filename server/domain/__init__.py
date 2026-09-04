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
from .models import (
    CardOwnership,
    FeatureUnlock,
    HomeStateSnapshot,
    PlayerProfile,
    PlayerResource,
    Unit,
    UnitMember,
)
from .persistence import SCHEMA_VERSION, SQLiteDomainStore
from .providers import (
    Clock,
    FixedClock,
    IdGenerator,
    RandomSource,
    SeededRandomSource,
    SequentialIdGenerator,
    SystemClock,
)
from .repositories import MasterDataRepository, PlayerStateRepository

__all__ = [
    "CardOwnership",
    "ChangeOperation",
    "ChangeSet",
    "Clock",
    "EntityChange",
    "Evidence",
    "EvidenceKind",
    "EvidenceStatus",
    "FeatureUnlock",
    "FixedClock",
    "HomeStateSnapshot",
    "IdGenerator",
    "MasterDataRepository",
    "PlayerProfile",
    "PlayerResource",
    "PlayerStateRepository",
    "RandomSource",
    "ResourceChange",
    "Reward",
    "SCHEMA_VERSION",
    "SQLiteDomainStore",
    "SeededRandomSource",
    "SequentialIdGenerator",
    "SystemClock",
    "Unit",
    "UnitMember",
]
