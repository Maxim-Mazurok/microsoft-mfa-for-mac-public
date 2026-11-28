"""P02 remains offline. No real credentials used or provider calls made."""
from contextlib import redirect_stdout
from dataclasses import replace
import io
import json
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "diagnostic"))
import p02_prepare as x
import push_protocol as p


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.no_dns = patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS forbidden")).start()
        self.no_socket = patch.object(socket, "socket", side_effect=AssertionError("Sockets forbidden")).start()
        self.addCleanup(patch.stopall)
        self.raw = (ROOT / "diagnostic/fixtures/p02-synthetic-config.json").read_bytes()
        self.config = x.config_from_json(self.raw)

    def tearDown(self):
        self.no_dns.assert_not_called()
        self.no_socket.assert_not_called()

    def test_data_message_single_token_package_and_nonce_binding(self):
        request = x.build_one_data_message(self.config, "synthetic-fcm-token", "synthetic-oauth-token", "a" * 32)
        body = json.loads(request.body)
        self.assertEqual(request.url, "https://fcm.googleapis.com/v1/projects/synthetic-p02-project/messages:send")
        self.assertFalse(body["validate_only"])
        self.assertEqual(body["message"]["data"]["p02_nonce"], "a" * 32)
        self.assertEqual(body["message"]["android"]["restricted_package_name"], x.PACKAGE)
        self.assertNotIn("notification", body["message"])
        self.assertNotIn("topic", body["message"])
        self.assertEqual(request.headers["Authorization"], "Bearer synthetic-oauth-token")
        self.assertNotIn("synthetic-oauth-token", repr(request))

    def test_config_does_not_accept_unconfirmed_wrong_types_or_extra_fields(self):
        for change in ({"owned_project_confirmed": False}, {"sender_id": 123},
                       {"package": "another.app"}, {"certificate_sha1": "0" * 40}):
            obj = dict(json.loads(self.raw), **change)
            with self.assertRaises(p.ProtocolError):
                x.config_from_json(json.dumps(obj).encode())
        with self.assertRaises(p.ProtocolError):
            x.config_from_json(b'{"owned_project_confirmed":true,"owned_project_confirmed":true}')

    def test_message_rejects_header_injection_wrong_package_and_nonce(self):
        for token in ("a\r\nInjected: secret", "", "token with spaces"):
            with self.assertRaises(p.ProtocolError):
                x.build_one_data_message(self.config, "synthetic", token, "a" * 32)
        with self.assertRaises(p.ProtocolError):
            x.build_one_data_message(replace(self.config, package="other.app"), "synthetic", "synthetic", "a" * 32)
        with self.assertRaises(p.ProtocolError):
            x.build_one_data_message(self.config, "synthetic", "synthetic", "not-a-nonce")

    def test_private_config_modes_and_paths(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "work") as directory:
            path = Path(directory) / "config.json"
            path.write_bytes(self.raw)
            path.chmod(0o600)
            self.assertEqual(x.private_config(path), self.raw)
            path.chmod(0o644)
            with self.assertRaises(p.ProtocolError):
                x.private_config(path)
            link = Path(directory) / "link"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                x.private_config(link)

    def test_preparation_only_reports_bounds_not_inputs(self):
        result = x.prepare(self.config)
        self.assertEqual(result["network_requests"], 0)
        self.assertFalse(result["read_p01_credentials"])
        self.assertFalse(result["live_executor_included"])
        self.assertEqual(result["prospective_limits"]["new_google_checkins"], 0)
        self.assertEqual(result["prospective_limits"]["fcm_data_message_posts"], 1)
        self.assertNotIn(self.config.api_key, json.dumps(result))
        self.assertNotIn(self.config.project_id, json.dumps(result))

    def test_cli_demo_and_no_live_mode(self):
        for argv, expected in (([], 0), (["demo"], 0), (["live", "synthetic-secret"], 2)):
            output = io.StringIO()
            with redirect_stdout(output):
                result = x.main(argv)
            self.assertEqual(result, expected)
            self.assertNotIn("synthetic-secret", output.getvalue())


if __name__ == "__main__":
    unittest.main()
