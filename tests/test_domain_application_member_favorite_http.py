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
    MemberFavoriteEditConfig,
    SQLiteDomainLoadIndexData,
    SQLiteMemberFavoriteEditHandler,
)
from server.application_http import create_application_server
from server.domain import CardOwnership, FixedClock, PlayerProfile, SQLiteDomainStore


def synthetic_header_encode(value: str) -> str:
    groups = "".join("12" + chr(ord(ch) + 10) + "3" for ch in value)
    return f"{len(value):04x}" + groups + ("7" * 32)


class MemberFavoriteEditHTTPIntegrationTests(unittest.TestCase):
    def test_encrypted_favorite_edit_round_trip_is_durable_idempotent_and_atomic_on_bad_identity(self) -> None:
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            domain_path = tmp_path / "domain.sqlite3"
            identity_path = tmp_path / "compat.sqlite3"
            now = datetime(2026, 9, 5, 8, 0, tzinfo=timezone.utc)
            clock = FixedClock(now)

            with SQLiteDomainStore.open(
                domain_path,
                master_revision="10133800",
                resource_revision="10133800",
            ) as domain:
                domain.save_profile(
                    PlayerProfile("archival-player", "Archive Producer", 1, 0, now, now)
                )
                for index, master_id in enumerate((100001, 100002), start=1):
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

            with SQLiteCompatibilityIdentityStore.open(identity_path) as identities:
                self.assertEqual(
                    identities.ensure_card_serial("archival-player", "card:1"),
                    1,
                )
                self.assertEqual(
                    identities.ensure_card_serial("archival-player", "card:2"),
                    2,
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
            favorite_edit = SQLiteMemberFavoriteEditHandler(
                domain_path,
                identity_path,
                config=MemberFavoriteEditConfig("archival-player"),
                master_revision="10133800",
                resource_revision="10133800",
            )
            server = create_application_server(
                "127.0.0.1",
                0,
                application_handlers={"/favorite/edit": favorite_edit},
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

            def post(request: dict) -> tuple[int, bytes]:
                body = cgss_codec.encode_body(
                    request,
                    udid,
                    dynamic_key=b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
                )
                conn = http.client.HTTPConnection(host, port, timeout=5)
                conn.request("POST", "/favorite/edit", body=body, headers=headers)
                response = conn.getresponse()
                payload = response.read()
                status = response.status
                conn.close()
                return status, payload

            def favorite_states() -> tuple[bool, bool]:
                with SQLiteDomainStore.open(
                    domain_path,
                    master_revision="10133800",
                    resource_revision="10133800",
                ) as domain:
                    cards = domain.list_cards("archival-player")
                    by_id = {card.user_card_id: card for card in cards}
                    return by_id["card:1"].favorite, by_id["card:2"].favorite

            try:
                request = {"serial_ids": [1, 2], "change_flags": [1, 0]}
                status, payload = post(request)
                self.assertEqual(status, 200, payload)
                self.assertEqual(cgss_codec.decode_body(payload, udid)["data"], {})
                self.assertEqual(favorite_states(), (True, False))

                # Explicit desired-state semantics make an exact replay a no-op,
                # while remaining a successful encrypted application exchange.
                status, payload = post(request)
                self.assertEqual(status, 200, payload)
                self.assertEqual(cgss_codec.decode_body(payload, udid)["data"], {})
                self.assertEqual(favorite_states(), (True, False))

                # The first assignment would clear card:1, but identity resolution
                # must finish for the whole batch before the domain command runs.
                status, payload = post(
                    {"serial_ids": [1, 999], "change_flags": [0, 1]}
                )
                self.assertEqual(status, 400, payload)
                self.assertEqual(favorite_states(), (True, False))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
