"""Application controller for final-client A:22 ``favorite/edit``.

This layer keeps compatibility serial IDs out of the preservation domain.  It
resolves the whole request through the persistent compatibility identity map
before issuing the explicit favorite-state command, so an unknown serial cannot
leave a partially mutated archival profile.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from server.adapters.identity_store import SQLiteCompatibilityIdentityStore
from server.adapters.member_favorite import parse_member_favorite_edit_request
from server.domain import ChangeSet, SQLiteDomainStore
from server.domain.card_services import PreservationCardService


@dataclass(frozen=True)
class MemberFavoriteEditConfig:
    player_id: str

    def __post_init__(self) -> None:
        if not self.player_id:
            raise ValueError("player_id must be non-empty")


class MemberFavoriteEditController:
    """Resolve compatibility identities and apply one explicit favorite batch."""

    def __init__(
        self,
        cards: PreservationCardService,
        identities: SQLiteCompatibilityIdentityStore,
        *,
        config: MemberFavoriteEditConfig,
    ) -> None:
        self._cards = cards
        self._identities = identities
        self._config = config

    def apply(self, raw_request: Any) -> ChangeSet:
        request = parse_member_favorite_edit_request(raw_request)
        if len(set(request.serial_ids)) != len(request.serial_ids):
            raise ValueError("duplicate favorite/edit serial IDs have unresolved semantics")

        player_id = self._config.player_id
        assignments: list[tuple[str, bool]] = []
        for serial_id, raw_flag in zip(
            request.serial_ids,
            request.change_flags,
            strict=True,
        ):
            user_card_id = self._identities.get_user_card_id(player_id, serial_id)
            if user_card_id is None:
                raise ValueError(
                    f"favorite/edit serial {serial_id} is not bound to an owned archival card"
                )
            # Exact final-client evidence closes the command as an explicit desired
            # boolean state.  The adapter deliberately keeps the int[] wire values
            # raw; treating non-zero as true is permissive compatibility behavior,
            # not a claim that production accepted arbitrary integer encodings.
            assignments.append((user_card_id, raw_flag != 0))

        return self._cards.set_favorites(player_id, tuple(assignments))

    def handle(self, raw_request: Any) -> dict[str, object]:
        self.apply(raw_request)
        # No endpoint-specific response projection is currently preserved in the
        # repository.  Keep the compatibility envelope minimal until exact Parse
        # evidence or device observation requires additional data.
        return {}


class SQLiteMemberFavoriteEditHandler:
    """Thread-safe callable opening short-lived SQLite stores per HTTP request."""

    def __init__(
        self,
        domain_path: str | Path,
        identity_path: str | Path,
        *,
        config: MemberFavoriteEditConfig,
        master_revision: str | None = None,
        resource_revision: str | None = None,
    ) -> None:
        self._domain_path = Path(domain_path)
        self._identity_path = Path(identity_path)
        self._config = config
        self._master_revision = master_revision
        self._resource_revision = resource_revision

    def __call__(self, raw_request: Any) -> dict[str, object]:
        with SQLiteDomainStore.open(
            self._domain_path,
            master_revision=self._master_revision,
            resource_revision=self._resource_revision,
        ) as domain:
            with SQLiteCompatibilityIdentityStore.open(self._identity_path) as identities:
                controller = MemberFavoriteEditController(
                    PreservationCardService(domain),
                    identities,
                    config=self._config,
                )
                return controller.handle(raw_request)
