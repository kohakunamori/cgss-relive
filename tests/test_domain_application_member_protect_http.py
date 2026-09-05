from __future__ import annotations

from datetime import datetime, timezone
import http.client
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import unittest

from server import cgss_codec
from server.adapters.identity_store import SQLiteCompatibilityIdentityStore
from server.application import (
    DomainLoadIndexConfig,
    MemberProtectConfig,
    SQLiteDomainLoadIndexData,
    SQLiteMemberProtectHandler,
)
from server.application_http import create_application_server
from server.domain import (
    BootstrapPolicy,
    FixedClock,
    PreservationProfileService,
    SQLiteDomainStore,
    SequentialIdGenerator,
    StarterCardGrant,
)
from server.minimal_profile import STARTER_WORK_CARD_SECTION


def synthetic_header_encode(value: str) -> str:
    groups = "".join("12" + chr(ord(ch) + 10) + "3" for ch in value)
    return f"{len(value):04x}" + groups + ("7" * 32)


class MemberProtectHTTPIntegrationTests(unittest.TestCase):
    def test_encrypted_member_protect_round_trip_persists_into_load_index(self) -> None:
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            domain_path = tmp_path / "domain.sqlite3"
            identity_path = tmp_path / "compat.sqlite3"
            clock = FixedClock(datetime(2026, 9, 5, 6, 0, tzinfo=timezone.utc))

            with SQLiteDomainStore.open(
                domain_path,
                master_revision="10133800",
                resource_revision="10133800",
            ) as domain:
                profiles = PreservationProfileService(
                    domain,
                    clock=clock,
                    ids=SequentialIdGenerator(),
                )
                profiles.bootstrap_profile(
                    BootstrapPolicy(
                        name="Archive Producer",
                        starter_cards=(StarterCardGrant(100001, skill_level=1),),
                    ),
                    player_id="archival-player",
                )
            with SQLiteCompatibilityIdentityStore.open(identity_path) as identities:
                self.assertEqual(
                    identities.ensure_card_serial("archival-player", "card:1"),
                    1,
                )

            load_index_data = SQLiteDomainLoadIndexData(
                domain_path,
                identity_path,
                clock=clock,
                config=DomainLoadIndexConfig(
                    player_id="archival-player",
                    viewer_id=7,
                    leader_user_card_id="card:1",
                ),
                master_revision="10133800",
                resource_revision="10133800",
            )
            member_protect = SQLiteMemberProtectHandler(
                domain_path,
                identity_path,
                clock=clock,
                config=MemberProtectConfig("archival-player"),
                master_revision="10133800",
                resource_revision="10133800",
            )

            server = create_application_server(
                "127.0.0.1",
                0,
                application_handlers={"/member/protect_card": member_protect},
                final_res_ver="10133800",
                load_index_data=load_index_data,
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            host, port = server.server_address[:2]
            udid = "00112233-4455-6677-8899-aabbccddeeff"
            headers = {
                "Content-Type": "application/octet-stream",
                "UDID": synthetic_header_encode(udid),
                "RES-VER": "10133800",
                "SID": "synthetic-sid",
                "APP-VER": "11.6.3",
            }

            def post(route: str, request: dict) -> dict:
                body = cgss_codec.encode_body(
                    request,
                    udid,
                    dynamic_key=b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
                )
                conn = http.client.HTTPConnection(host, port, timeout=5)
                conn.request("POST", route, body=body, headers=headers)
                response = conn.getresponse()
                payload = response.read()
                self.assertEqual(response.status, 200, payload)
                decoded = cgss_codec.decode_body(payload, udid)
                conn.close()
                return decoded

            def load_card() -> dict:
                decoded = post(
                    "/load/index",
                    {
                        "campaign_data": "",
                        "campaign_user": 0,
                        "campaign_sign": "",
                        "app_type": 0,
                        "viewer_id": "opaque-viewer-id",
                        "timezone": "+09:00:00",
                    },
                )
                cards = decoded["data"][STARTER_WORK_CARD_SECTION]
                self.assertEqual(len(cards), 1)
                return cards[0]

            try:
                before = load_card()
                self.assertEqual(before["serial_id"], 1)
                self.assertEqual(before["protect"], 0)

                first = post("/member/protect_card", {"serial_ids": [1]})
                self.assertEqual(first["data"], {"protect_card_list": [1]})
                after_first = load_card()
                self.assertEqual(after_first["serial_id"], 1)
                self.assertEqual(after_first["protect"], 1)

                second = post("/member/protect_card", {"serial_ids": [1]})
                self.assertEqual(second["data"], {"protect_card_list": []})
                after_second = load_card()
                self.assertEqual(after_second["serial_id"], 1)
                self.assertEqual(after_second["protect"], 0)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
