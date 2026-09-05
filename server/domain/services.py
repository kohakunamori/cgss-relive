"""Initial D1 application/domain services for archival profile bootstrap and Home.

Bootstrap defaults are explicit preservation policy, not reconstructed production
server behavior. CGSS endpoint adapters should call these services rather than
write persistence rows directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Mapping

from .core import (
    ChangeOperation,
    ChangeSet,
    EntityChange,
    Evidence,
    EvidenceKind,
    EvidenceStatus,
    ResourceChange,
)
from .models import CardOwnership, FeatureUnlock, HomeStateSnapshot, PlayerProfile, PlayerResource
from .providers import Clock, IdGenerator
from .repositories import MasterDataRepository, PlayerStateRepository


_POLICY_EVIDENCE = Evidence(
    EvidenceStatus.CANDIDATE,
    EvidenceKind.POLICY,
    source="preservation-bootstrap-policy",
    note="project-selected archival bootstrap behavior; not production-server proof",
)

_CARD_PROTECTION_EVIDENCE = Evidence(
    EvidenceStatus.PROVEN_STATIC,
    EvidenceKind.EXACT,
    source="final-11.6.3 WorkCardData.CardData",
    note=(
        "response protect is stored in independent _isProtect state; "
        "endpoint command semantics are tracked separately"
    ),
)

_MEMBER_PROTECT_TOGGLE_EVIDENCE = Evidence(
    EvidenceStatus.PROVEN_STATIC,
    EvidenceKind.INFERRED,
    source="final-11.6.3 A:29 MemberProtect",
    note=(
        "A:29 accepts only serial_ids and returns data.protect_card_list; final client "
        "rebuilds requested-card protection from that authoritative membership list. "
        "Using a toggle command is the preservation inference for the single protect/"
        "unprotect action until runtime or stronger server-side evidence proves the "
        "production mutation algorithm."
    ),
)


@dataclass(frozen=True)
class StarterCardGrant:
    master_card_id: int
    level: int = 1
    experience: int = 0
    skill_level: int = 0
    star_lesson_step: int = 0
    love: int = 0
    is_protected: bool = False
    favorite: bool = False

    def __post_init__(self) -> None:
        if self.master_card_id <= 0:
            raise ValueError("starter master_card_id must be positive")
        if self.level < 1:
            raise ValueError("starter card level must be at least 1")
        if self.experience < 0 or self.skill_level < 0:
            raise ValueError("starter card progression must be non-negative")
        if self.star_lesson_step < 0 or self.love < 0:
            raise ValueError("starter card star_lesson_step/love must be non-negative")


@dataclass(frozen=True)
class InitialUnlock:
    kind: str
    master_ref_id: int
    source: str = "bootstrap-policy"

    def __post_init__(self) -> None:
        if not self.kind:
            raise ValueError("unlock kind must be non-empty")
        if self.master_ref_id <= 0:
            raise ValueError("unlock master_ref_id must be positive")
        if not self.source:
            raise ValueError("unlock source must be non-empty")


@dataclass(frozen=True)
class BootstrapPolicy:
    """Explicit deterministic defaults for a fresh preservation profile."""

    name: str
    producer_level: int = 1
    experience: int = 0
    initial_resources: Mapping[str, int] = field(default_factory=dict)
    starter_cards: tuple[StarterCardGrant, ...] = ()
    initial_unlocks: tuple[InitialUnlock, ...] = ()
    policy_name: str = "archival-bootstrap-v0"

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("bootstrap profile name must be non-empty")
        if self.producer_level < 1 or self.experience < 0:
            raise ValueError("invalid bootstrap profile progression")
        if not self.policy_name:
            raise ValueError("policy_name must be non-empty")

        resources = dict(self.initial_resources)
        for kind, amount in resources.items():
            if not kind:
                raise ValueError("initial resource kind must be non-empty")
            if amount < 0:
                raise ValueError("initial resource amount must be non-negative")
        object.__setattr__(self, "initial_resources", MappingProxyType(resources))
        object.__setattr__(self, "starter_cards", tuple(self.starter_cards))
        object.__setattr__(self, "initial_unlocks", tuple(self.initial_unlocks))


@dataclass(frozen=True)
class BootstrapResult:
    snapshot: HomeStateSnapshot
    changes: ChangeSet
    created: bool


class PreservationProfileService:
    """Profile/Home service independent of CGSS routes and serializers."""

    def __init__(
        self,
        repository: PlayerStateRepository,
        *,
        clock: Clock,
        ids: IdGenerator,
        master_data: MasterDataRepository | None = None,
    ) -> None:
        self._repository = repository
        self._clock = clock
        self._ids = ids
        self._master_data = master_data

    def _require_master(self, kind: str, master_id: int) -> None:
        if self._master_data is not None and not self._master_data.contains(kind, master_id):
            raise ValueError(f"unknown master reference {kind}:{master_id}")

    def bootstrap_profile(
        self,
        policy: BootstrapPolicy,
        *,
        player_id: str | None = None,
    ) -> BootstrapResult:
        resolved_player_id = player_id or self._ids.new_id("player")
        existing = self._repository.get_home_snapshot(resolved_player_id)
        if existing is not None:
            return BootstrapResult(existing, ChangeSet(), False)

        now = self._clock.now()
        profile = PlayerProfile(
            player_id=resolved_player_id,
            name=policy.name,
            producer_level=policy.producer_level,
            experience=policy.experience,
            created_at=now,
            last_login_at=now,
        )

        resource_changes: list[ResourceChange] = []
        entity_changes: list[EntityChange] = []

        with self._repository.transaction():
            self._repository.save_profile(profile)

            for kind, amount in sorted(policy.initial_resources.items()):
                self._repository.set_resource(PlayerResource(resolved_player_id, kind, amount))
                if amount:
                    resource_changes.append(ResourceChange(kind, amount, resulting_amount=amount))

            for grant in policy.starter_cards:
                self._require_master("card", grant.master_card_id)
                user_card_id = self._ids.new_id("card")
                card = CardOwnership(
                    user_card_id=user_card_id,
                    player_id=resolved_player_id,
                    master_card_id=grant.master_card_id,
                    level=grant.level,
                    experience=grant.experience,
                    skill_level=grant.skill_level,
                    star_lesson_step=grant.star_lesson_step,
                    love=grant.love,
                    is_protected=grant.is_protected,
                    favorite=grant.favorite,
                    acquired_at=now,
                )
                self._repository.save_card(card)
                entity_changes.append(
                    EntityChange(
                        category="card",
                        entity_id=user_card_id,
                        operation=ChangeOperation.CREATE,
                        values={"master_card_id": grant.master_card_id},
                        evidence=_POLICY_EVIDENCE,
                    )
                )

            for initial_unlock in policy.initial_unlocks:
                self._require_master(initial_unlock.kind, initial_unlock.master_ref_id)
                unlock = FeatureUnlock(
                    player_id=resolved_player_id,
                    unlock_kind=initial_unlock.kind,
                    master_ref_id=initial_unlock.master_ref_id,
                    unlocked_at=now,
                    source=initial_unlock.source,
                )
                self._repository.save_feature_unlock(unlock)
                entity_changes.append(
                    EntityChange(
                        category="feature-unlock",
                        entity_id=f"{initial_unlock.kind}:{initial_unlock.master_ref_id}",
                        operation=ChangeOperation.CREATE,
                        values={
                            "unlock_kind": initial_unlock.kind,
                            "master_ref_id": initial_unlock.master_ref_id,
                        },
                        evidence=_POLICY_EVIDENCE,
                    )
                )

        snapshot = self._repository.get_home_snapshot(resolved_player_id)
        if snapshot is None:  # defensive: transaction succeeded, so profile must exist
            raise RuntimeError("bootstrap transaction completed without persisted profile")

        return BootstrapResult(
            snapshot=snapshot,
            changes=ChangeSet(
                profile_changed=True,
                resources=tuple(resource_changes),
                entities=tuple(entity_changes),
                metadata={"bootstrap_policy": policy.policy_name},
            ),
            created=True,
        )

    def get_home_snapshot(self, player_id: str) -> HomeStateSnapshot:
        snapshot = self._repository.get_home_snapshot(player_id)
        if snapshot is None:
            raise KeyError(f"unknown archival player {player_id!r}")
        return snapshot

    def set_card_protection(
        self,
        player_id: str,
        user_card_id: str,
        is_protected: bool,
    ) -> ChangeSet:
        """Set the proven card-protection state for one owned card instance."""

        card = next(
            (
                candidate
                for candidate in self._repository.list_cards(player_id)
                if candidate.user_card_id == user_card_id
            ),
            None,
        )
        if card is None:
            raise KeyError(
                f"unknown owned card {user_card_id!r} for archival player {player_id!r}"
            )
        desired = bool(is_protected)
        if card.is_protected == desired:
            return ChangeSet()

        updated = replace(card, is_protected=desired)
        with self._repository.transaction():
            self._repository.save_card(updated)

        return ChangeSet(
            entities=(
                EntityChange(
                    category="card",
                    entity_id=user_card_id,
                    operation=ChangeOperation.UPDATE,
                    values={"is_protected": desired},
                    evidence=_CARD_PROTECTION_EVIDENCE,
                ),
            )
        )

    def toggle_card_protection(
        self,
        player_id: str,
        user_card_ids: tuple[str, ...],
    ) -> ChangeSet:
        """Atomically toggle protection for a batch of owned cards.

        The durable protection field and response membership semantics are exact
        final-client evidence.  Toggle is intentionally marked *inferred*: A:29 has
        one serial-id-only request for both protect/unprotect UI actions, but the
        production server's internal mutation code is not available.

        Duplicate IDs are rejected rather than assigned an invented sequential or
        set-normalization meaning.  The untouched client is expected to submit each
        selected owned-card serial once.
        """

        requested = tuple(user_card_ids)
        if any(not user_card_id for user_card_id in requested):
            raise ValueError("user_card_ids must be non-empty identities")
        if len(set(requested)) != len(requested):
            raise ValueError("duplicate card identities have unresolved toggle semantics")
        if not requested:
            return ChangeSet()

        cards = {card.user_card_id: card for card in self._repository.list_cards(player_id)}
        missing = [user_card_id for user_card_id in requested if user_card_id not in cards]
        if missing:
            raise KeyError(
                f"unknown owned cards for archival player {player_id!r}: {missing!r}"
            )

        updates = [replace(cards[user_card_id], is_protected=not cards[user_card_id].is_protected) for user_card_id in requested]
        with self._repository.transaction():
            for card in updates:
                self._repository.save_card(card)

        return ChangeSet(
            entities=tuple(
                EntityChange(
                    category="card",
                    entity_id=card.user_card_id,
                    operation=ChangeOperation.UPDATE,
                    values={"is_protected": card.is_protected},
                    evidence=_MEMBER_PROTECT_TOGGLE_EVIDENCE,
                )
                for card in updates
            ),
            metadata={"command_semantics": "member-protect-toggle-inferred"},
        )
