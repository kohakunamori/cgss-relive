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
from .master_data import MasterTableSpec, SQLiteMasterDataRepository
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
from .services import (
    BootstrapPolicy,
    BootstrapResult,
    InitialUnlock,
    PreservationProfileService,
    StarterCardGrant,
)

__all__ = [
    "BootstrapPolicy",
    "BootstrapResult",
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
    "InitialUnlock",
    "MasterDataRepository",
    "MasterTableSpec",
    "PlayerProfile",
    "PlayerResource",
    "PlayerStateRepository",
    "PreservationProfileService",
    "RandomSource",
    "ResourceChange",
    "Reward",
    "SCHEMA_VERSION",
    "SQLiteDomainStore",
    "SQLiteMasterDataRepository",
    "SeededRandomSource",
    "SequentialIdGenerator",
    "StarterCardGrant",
    "SystemClock",
    "Unit",
    "UnitMember",
]
