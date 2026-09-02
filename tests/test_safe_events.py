from __future__ import annotations

import json
import pathlib
import tempfile
import unittest

from server.safe_events import SafeEventLog, build_event


class SafeEventTests(unittest.TestCase):
    def test_event_excludes_sensitive_headers_and_values(self) -> None:
        event = build_event(
            route="/load/check",
            status=200,
            timestamp=1.0,
            headers={
                "APP-VER": "11.6.3",
                "RES-VER": "10133800",
                "UDID": "secret-udid",
                "SID": "secret-sid",
                "USER-ID": "secret-user",
                "PARAM": "secret-param",
            },
            request={"viewer_id": "secret-viewer", "timezone": "+09:00:00"},
            response={
                "data_headers": {"result_code": 1, "sid": "secret-response-sid"},
                "data": {"user_info": {"name": "secret-name"}},
            },
        )
        encoded = json.dumps(event, sort_keys=True)
        for secret in (
            "secret-udid",
            "secret-sid",
            "secret-user",
            "secret-param",
            "secret-viewer",
            "secret-response-sid",
            "secret-name",
        ):
            self.assertNotIn(secret, encoded)
        self.assertEqual(event["headers"], {"APP-VER": "11.6.3", "RES-VER": "10133800"})
        self.assertEqual(event["request_keys"], ["timezone", "viewer_id"])
        self.assertEqual(event["response_data_keys"], ["user_info"])
        self.assertEqual(event["response_data_headers"], {"result_code": 1})

    def test_api_candidates_are_public_identity_only(self) -> None:
        event = build_event(
            route="/bn_consent/get_state",
            status=404,
            timestamp=1.0,
            api_candidates=[
                {"group": "A", "key": 14, "name": "BnContentGetState", "literal_index": 23438},
            ],
        )
        self.assertEqual(
            event["api_candidates"],
            [{"group": "A", "key": 14, "name": "BnContentGetState", "literal_index": 23438}],
        )

    def test_jsonl_writer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "events.jsonl"
            log = SafeEventLog(path)
            log.append({"route": "/load/title", "status": 200})
            log.append({"route": "/load/index", "status": 503})
            rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual([row["route"] for row in rows], ["/load/title", "/load/index"])


if __name__ == "__main__":
    unittest.main()
