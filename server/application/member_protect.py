"""Application controller for final-client A:29 ``member/protect_card``.

This layer composes the exact client request/response shapes with the persistent
compatibility identity map and preservation-domain mutation command. HTTP/encryption
remain outside this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from server.adapters.identity_store import SQLiteCompatibilityIdentityStore
from server.adapters.member_protect import (
    parse_member_protect_request,
    project_member_protect_response_data,
)
from server.domain import (
    Clock,
    PreservationProfileService,
    SQLiteDomainStore,
    SequentialIdGenerator,
)


@dataclass(frozen=True)
class MemberProtectConfig:
    player_id: str

    def __post_init__(self) -> None:
        if not self.player_id:
            raise ValueError("player_id must be non-empty")


class MemberProtectController:
    """Resolve client serials, mutate domain state, and return exact response data."""

    def __init__(
        self,
        profile_service: PreservationProfileService,
        identities: SQLiteCompatibilityIdentityStore,
        *,
        config: MemberProtectConfig,
    ) -> None:
        self._profiles = profile_service
        self._identities = identities
        self._config = config

    def handle(self, raw_request: Any) -> dict[str, object]:
        request = parse_member_protect_request(raw_request)
        if len(set(request.serial_ids)) != len(request.serial_ids):
            # Exact request metadata permits int[], but duplicate server mutation
            # semantics are not recovered. Reject instead of inventing double-toggle
            # or set-normalization behavior.
            raise ValueError("duplicate member/protect serial IDs have unresolved semantics")

        player_id = self._config.player_id
        user_card_ids: list[str] = []
        for serial_id in request.serial_ids:
            user_card_id = self._identities.get_user_card_id(player_id, serial_id)
            if user_card_id is None:
                raise ValueError(
                    f"member/protect serial {serial_id} is not bound to an owned archival card"
                )
            user_card_ids.append(user_card_id)

        self._profiles.toggle_card_protection(player_id, tuple(user_card_ids))

        snapshot = self._profiles.get_home_snapshot(player_id)
        protected_by_id = {
            card.user_card_id for card in snapshot.cards if card.is_protected
        }
        protected_requested_serials = [
            serial_id
            for serial_id, user_card_id in zip(request.serial_ids, user_card_ids, strict=True)
            if user_card_id in protected_by_id
        ]
        return project_member_protect_response_data(
            request,
            protected_requested_serials,
        )


class SQLiteMemberProtectHandler:
    """Thread-safe callable opening short-lived SQLite stores per HTTP request."""

    def __init__(
        self,
        domain_path: str | Path,
        identity_path: str | Path,
        *,
        clock: Clock,
        config: MemberProtectConfig,
        master_revision: str | None = None,
        resource_revision: str | None = None,
    ) -> None:
        self._domain_path = Path(domain_path)
        self._identity_path = Path(identity_path)
        self._clock = clock
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
                profiles = PreservationProfileService(
                    domain,
                    clock=self._clock,
                    ids=SequentialIdGenerator(),
                )
                controller = MemberProtectController(
                    profiles,
                    identities,
                    config=self._config,
                )
                return controller.handle(raw_request)
