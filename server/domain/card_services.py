"""Card-state domain commands independent of CGSS route/DTO details."""

from __future__ import annotations

from dataclasses import replace

from .core import ChangeOperation, ChangeSet, EntityChange, Evidence, EvidenceKind, EvidenceStatus
from .repositories import PlayerStateRepository


_CARD_FAVORITE_EVIDENCE = Evidence(
    EvidenceStatus.PROVEN_STATIC,
    EvidenceKind.EXACT,
    source="final-11.6.3 A:22 MemberFavoriteEdit",
    note=(
        "final client keeps per-card favorite edit state as boolean WorkFavoriteData "
        "change flags and serializes one explicit desired flag alongside each card serial"
    ),
)


class PreservationCardService:
    """Mutate durable owned-card state without exposing client compatibility IDs."""

    def __init__(self, repository: PlayerStateRepository) -> None:
        self._repository = repository

    def set_favorites(
        self,
        player_id: str,
        assignments: tuple[tuple[str, bool], ...],
    ) -> ChangeSet:
        """Atomically set favorite state for a batch of owned card instances.

        The command is an explicit set operation, not a toggle.  All identities are
        validated before any write so a malformed compatibility request cannot leave
        a partially updated archival profile.
        """

        requested = tuple(assignments)
        if not player_id:
            raise ValueError("player_id must be non-empty")
        if any(not user_card_id for user_card_id, _ in requested):
            raise ValueError("favorite card identities must be non-empty")
        identities = tuple(user_card_id for user_card_id, _ in requested)
        if len(set(identities)) != len(identities):
            raise ValueError("duplicate favorite card identities have unresolved semantics")
        if not requested:
            return ChangeSet()

        cards = {card.user_card_id: card for card in self._repository.list_cards(player_id)}
        missing = [user_card_id for user_card_id in identities if user_card_id not in cards]
        if missing:
            raise KeyError(
                f"unknown owned cards for archival player {player_id!r}: {missing!r}"
            )

        updates = []
        for user_card_id, favorite in requested:
            card = cards[user_card_id]
            desired = bool(favorite)
            if card.favorite != desired:
                updates.append(replace(card, favorite=desired))

        if not updates:
            return ChangeSet()

        with self._repository.transaction():
            for card in updates:
                self._repository.save_card(card)

        return ChangeSet(
            entities=tuple(
                EntityChange(
                    category="card",
                    entity_id=card.user_card_id,
                    operation=ChangeOperation.UPDATE,
                    values={"favorite": card.favorite},
                    evidence=_CARD_FAVORITE_EVIDENCE,
                )
                for card in updates
            ),
            metadata={"command_semantics": "member-favorite-explicit-set"},
        )
