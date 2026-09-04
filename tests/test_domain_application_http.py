from __future__ import annotations

from datetime import datetime, timezone
import http.client
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import unittest

from server import cgss_codec
from server.application import DomainLoadIndexConfig, DomainLoadIndexController, DynamicLoadIndexData
from server.adapters.identity_store import SQLiteCompatibilityIdentityStore
from server.domain import (
    BootstrapPolicy,
    FixedClock,
    PlayerResource,
    PreservationProfileService,
    SQLiteDomainStore,
    SequentialIdGenerator,
    StarterCardGrant,
)
from server.http_server import create_server


def synthetic_header_encode(value: str) -> str:
    groups = "".join("12" + chr(ord(ch) + 10) + "3" for ch in value)
    return f"{len(value):04x}" + groups + ("7" * 32)


class DomainBackedHTTPTests(unittest.TestCase):
    def test_load_index_reflects_domain_mutation_between_requests(self) -> None:
        with TemporaryDirectory() as tmp:
            clock = FixedClock(datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc))
            domain = SQLiteDomainStore.open(Path(tmp) / "domain.sqlite3", master_revision="10133800")
            identities = SQLiteCompatibilityIdentityStore.open(Path(tmp) / "compat.sqlite3")
            service = PreservationProfileService(
                domain,
                clock=clock,
                ids=SequentialIdGenerator(),
            )
            controller = DomainLoadIndexController(
                service,
                identities,
                clock=clock,
                config=DomainLoadIndexConfig(
                    player_id="archival-player",
                    viewer_id=7,
                    bootstrap_policy=BootstrapPolicy(
                        name="Relive Producer",
                        initial_resources={"stamina": 100},
                        starter_cards=(StarterCardGrant(100001, skill_level=1),),
                    ),
                ),
            )
            dynamic_data = DynamicLoadIndexData(controller)

            server = create_server(
                "127.0.0.1",
                0,
                final_res_ver="10133800",
                load_index_data=dynamic_data,
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            host, port = server.server_address[:2]
            udid = "00112233-4455-6677-8899-aabbccddeeff"

            def request_load_index() -> dict:
                request = {
                    "campaign_data": "",
                    "campaign_user": 0,
                    "campaign_sign": "",
                    "app_type": 0,
                    "viewer_id": "opaque-viewer-id",
                    "timezone": "+09:00:00",
                }
                body = cgss_codec.encode_body(
                    request,
                    udid,
                    dynamic_key=b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
                )
                headers = {
                    "Content-Type": "application/octet-stream",
                    "UDID": synthetic_header_encode(udid),
                    "RES-VER": "10133800",
                    "SID": "synthetic-sid",
                    "APP-VER": "11.6.3",
                }
                conn = http.client.HTTPConnection(host, port, timeout=5)
                conn.request("POST", "/load/index", body=body, headers=headers)
                response = conn.getresponse()
                self.assertEqual(response.status, 200)
                decoded = cgss_codec.decode_body(response.read(), udid)
                conn.close()
                return decoded["data"]

            try:
                first = request_load_index()
                self.assertEqual(first["user_info"]["stamina"], 100)
                domain.set_resource(PlayerResource("archival-player", "stamina", 42))
                second = request_load_index()
                self.assertEqual(second["user_info"]["stamina"], 42)
                self.assertEqual(
                    first["cs_gacha_data_cenere"][0]["serial_id"],
                    second["cs_gacha_data_cenere"][0]["serial_id"],
                )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
                identities.close()
                domain.close()


if __name__ == "__main__":
    unittest.main()
