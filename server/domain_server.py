"""Runnable domain-backed CGSS preservation API.

This application entry point serves mutable archival state rather than a fixed
load/index template. It currently registers:

* domain-backed ``/load/index``;
* A:29 ``/member/protect_card``;
* A:19 ``/unit/edit``.

Starter profile/card/unit values are explicit preservation provisioning policy, not
claims about the production account-creation service.
"""

from __future__ import annotations

import argparse
import ssl
from pathlib import Path

from .application import (
    DomainLoadIndexConfig,
    MemberProtectConfig,
    MemberUnitEditConfig,
    SQLiteDomainLoadIndexData,
    SQLiteMemberProtectHandler,
    SQLiteMemberUnitEditHandler,
)
from .application_http import create_application_server
from .domain import (
    BootstrapPolicy,
    PreservationProfileService,
    SQLiteDomainStore,
    SequentialIdGenerator,
    StarterCardGrant,
    SystemClock,
    Unit,
    UnitMember,
)
from .load_check import FINAL_RESOURCE_VERSION


DEFAULT_PLAYER_ID = "archival-player"
DEFAULT_VIEWER_ID = 1
DEFAULT_STARTER_CARD_ID = 100001


def provision_archival_profile(
    domain_path: str | Path,
    *,
    player_id: str,
    producer_name: str,
    starter_card_id: int,
    initial_stamina: int,
    master_revision: str,
    resource_revision: str,
) -> str:
    """Ensure one deterministic archival profile and starter unit exist.

    Returns the domain user-card ID used as the load/index leader. Unit creation is
    provisioning policy and intentionally stays out of endpoint/domain command
    semantics.
    """

    if not player_id:
        raise ValueError("player_id must be non-empty")
    if not producer_name:
        raise ValueError("producer_name must be non-empty")
    if starter_card_id <= 0:
        raise ValueError("starter_card_id must be positive")
    if initial_stamina < 0:
        raise ValueError("initial_stamina must be non-negative")

    clock = SystemClock()
    with SQLiteDomainStore.open(
        domain_path,
        master_revision=master_revision,
        resource_revision=resource_revision,
    ) as domain:
        profiles = PreservationProfileService(
            domain,
            clock=clock,
            ids=SequentialIdGenerator(),
        )
        profiles.bootstrap_profile(
            BootstrapPolicy(
                name=producer_name,
                initial_resources={"stamina": initial_stamina},
                starter_cards=(StarterCardGrant(starter_card_id, skill_level=1),),
                policy_name="domain-server-starter-v0",
            ),
            player_id=player_id,
        )
        snapshot = profiles.get_home_snapshot(player_id)
        if not snapshot.cards:
            raise RuntimeError("archival provisioning has no owned card")
        leader = snapshot.cards[0].user_card_id
        if not snapshot.units:
            domain.save_unit(
                Unit(
                    unit_id="unit:starter",
                    player_id=player_id,
                    slot=0,
                    name="Relive Unit",
                    members=tuple(
                        UnitMember(position, card.user_card_id)
                        for position, card in enumerate(snapshot.cards[:5])
                    ),
                )
            )
        return leader


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the domain-backed CGSS preservation API")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--domain-db", type=Path, required=True)
    parser.add_argument("--identity-db", type=Path, required=True)
    parser.add_argument("--player-id", default=DEFAULT_PLAYER_ID)
    parser.add_argument("--viewer-id", type=int, default=DEFAULT_VIEWER_ID)
    parser.add_argument("--producer-name", default="Relive Producer")
    parser.add_argument("--starter-card-id", type=int, default=DEFAULT_STARTER_CARD_ID)
    parser.add_argument("--initial-stamina", type=int, default=100)
    parser.add_argument("--master-revision", default=FINAL_RESOURCE_VERSION)
    parser.add_argument("--resource-revision", default=FINAL_RESOURCE_VERSION)
    parser.add_argument("--event-log", type=Path)
    parser.add_argument("--cert")
    parser.add_argument("--key")
    return parser


def main() -> int:
    parser = build_argument_parser()
    args = parser.parse_args()
    if bool(args.cert) != bool(args.key):
        parser.error("--cert and --key must be supplied together")
    if args.viewer_id <= 0:
        parser.error("--viewer-id must be positive")

    args.domain_db.parent.mkdir(parents=True, exist_ok=True)
    args.identity_db.parent.mkdir(parents=True, exist_ok=True)
    try:
        leader_user_card_id = provision_archival_profile(
            args.domain_db,
            player_id=args.player_id,
            producer_name=args.producer_name,
            starter_card_id=args.starter_card_id,
            initial_stamina=args.initial_stamina,
            master_revision=args.master_revision,
            resource_revision=args.resource_revision,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        parser.error(f"failed to provision domain profile: {exc}")

    clock = SystemClock()
    load_index_data = SQLiteDomainLoadIndexData(
        args.domain_db,
        args.identity_db,
        clock=clock,
        config=DomainLoadIndexConfig(
            player_id=args.player_id,
            viewer_id=args.viewer_id,
            leader_user_card_id=leader_user_card_id,
        ),
        master_revision=args.master_revision,
        resource_revision=args.resource_revision,
    )
    member_protect = SQLiteMemberProtectHandler(
        args.domain_db,
        args.identity_db,
        clock=clock,
        config=MemberProtectConfig(args.player_id),
        master_revision=args.master_revision,
        resource_revision=args.resource_revision,
    )
    member_unit_edit = SQLiteMemberUnitEditHandler(
        args.domain_db,
        args.identity_db,
        config=MemberUnitEditConfig(args.player_id),
        master_revision=args.master_revision,
        resource_revision=args.resource_revision,
    )

    httpd = create_application_server(
        args.host,
        args.port,
        application_handlers={
            "/member/protect_card": member_protect,
            "/unit/edit": member_unit_edit,
        },
        final_res_ver=args.resource_revision,
        load_index_data=load_index_data,
        event_log=args.event_log,
    )

    scheme = "http"
    if args.cert and args.key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.cert, args.key)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"

    bound_host, bound_port = httpd.server_address[:2]
    print(f"cgss-relive domain API listening on {scheme}://{bound_host}:{bound_port}")
    print(f"domain DB: {args.domain_db}")
    print(f"compatibility identity DB: {args.identity_db}")
    print("dynamic routes: /load/index, /member/protect_card, /unit/edit")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
