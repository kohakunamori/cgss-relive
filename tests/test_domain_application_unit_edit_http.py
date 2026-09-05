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
    MemberUnitEditConfig,
    SQLiteDomainLoadIndexData,
    SQLiteMemberUnitEditHandler,
)
from server.application_http import create_application_server
from server.domain import (
    CardOwnership,
    FixedClock,
    PlayerProfile,
    SQLiteDomainStore,
    Unit,
    UnitMember,
)


def synthetic_header_encode(value: str) -> str:
    groups = "".join("12" + chr(ord(ch) + 10) + "3" for ch in value)
    return f"{len(value):04x}" + groups + ("7" * 32)


class MemberUnitEditHTTPIntegrationTests(unittest.TestCase):
    def test_encrypted_unit_edit_round_trip_persists_into_load_index(self) -> None:
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            domain_path = tmp_path / "domain.sqlite3"
            identity_path = tmp_path / "compat.sqlite3"
            now = datetime(2026, 9, 5, 7, 0, tzinfo=timezone.utc)
            clock = FixedClock(now)

            with SQLiteDomainStore.open(
                domain_path,
                master_revision="10133800",
                resource_revision="10133800",
            ) as domain:
                domain.save_profile(
                    PlayerProfile("archival-player", "Archive Producer", 1, 0, now, now)
                )
                for index, master_id in enumerate((100001, 100002, 100003), start=1):
                    domain.save_card(
                        CardOwnership(
                            user_card_id=f"card:{index}",
                            player_id="archival-player",
                            master_card_id=master_id,
                            level=1,
                            experience=0,
                            skill_level=1,
                            star_lesson_step=0,
                            love=0,
                            is_protected=False,
                            favorite=False,
                            acquired_at=now,
                        )
                    )
                domain.save_unit(
                    Unit(
                        unit_id="unit:1",
                        player_id="archival-player",
                        slot=0,
                        name="Primary",
                        members=(UnitMember(0, "card:1"), UnitMember(1, "card:2")),
                    )
                )

            with SQLiteCompatibilityIdentityStore.open(identity_path) as identities:
                for index in range(1, 4):
                    self.assertEqual(
                        identities.ensure_card_serial("archival-player", f"card:{index}"),
                        index,
                    )
                self.assertEqual(
                    identities.ensure_unit_id("archival-player", "unit:1"),
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
            unit_edit = SQLiteMemberUnitEditHandler(
                domain_path,
                identity_path,
                config=MemberUnitEditConfig("archival-player"),
                master_revision="10133800",
                resource_revision="10133800",
            )

            server = create_application_server(
                "127.0.0.1",
                0,
                application_handlers={"/unit/edit": unit_edit},
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

            def load_unit() -> dict:
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
                units = decoded["data"]["user_unit_list"]
                self.assertEqual(len(units), 1)
                return units[0]

            request = {
                "unit_info_list": [
                    {
                        "unit_id": 1,
                        "serial_ids": [3, 0, 1, 0, 0],
                        "dress_types": [0, 0, 0, 0, 0],
                        "dress_2d_types": [0, 0, 0, 0, 0],
                        "dress_storage_ids": [0, 0, 0, 0, 0],
                    }
                ],
                "main_unit_id": 1,
            }

            try:
                before = load_unit()
                self.assertEqual(
                    [before[f"serial_id_{index}"] for index in range(5)],
                    [1, 2, 0, 0, 0],
                )

                response = post("/unit/edit", request)
                self.assertEqual(response["data"], {})

                after = load_unit()
                self.assertEqual(after["unit_id"], 1)
                self.assertEqual(
                    [after[f"serial_id_{index}"] for index in range(5)],
                    [3, 0, 1, 0, 0],
                )

                with SQLiteDomainStore.open(
                    domain_path,
                    master_revision="10133800",
                    resource_revision="10133800",
                ) as domain:
                    persisted = domain.list_units("archival-player")[0]
                    self.assertEqual(
                        persisted.members,
                        (UnitMember(0, "card:3"), UnitMember(2, "card:1")),
                    )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
