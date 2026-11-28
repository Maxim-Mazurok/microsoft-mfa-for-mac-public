"""Offline protocol tests. Fixtures are synthetic, independent wire vectors.

No external SDK import/startup, sockets, DNS, provider registration or enrollment.
"""
from dataclasses import replace
import gzip
import json
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import push_protocol as p

FIXTURE = json.loads((Path(__file__).resolve().parents[1] / "fixtures/push-synthetic.json").read_text())


class PushProtocolTests(unittest.TestCase):
    def setUp(self):
        self.dns = patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS forbidden")).start()
        self.sock = patch.object(socket, "socket", side_effect=AssertionError("Sockets forbidden")).start()
        self.addCleanup(patch.stopall)
        self.config = p.AndroidConfig("synthetic-project", "123", "1:123:android:abcd",
                                      "synthetic-api-key", "x.app", "ab" * 20,
                                      "syntheticApp", "0.1.0", "1")
        self.fid = "cAAAAAAAAAAAAAAAAAAAAA"
        self.installation = p.parse_fis_create(json.dumps(FIXTURE["fis"]).encode(), self.config, self.fid)
        self.credentials = p.parse_checkin(bytes.fromhex(FIXTURE["checkin_response_hex"]))

    def tearDown(self):
        self.dns.assert_not_called()
        self.sock.assert_not_called()

    def test_fid_known_uuid_and_entropy(self):
        self.assertEqual(p.new_fid(uuid.UUID(int=0)), self.fid)
        generated = {p.new_fid() for _ in range(128)}
        self.assertEqual(len(generated), 128)
        for fid in generated:
            self.assertRegex(fid, r"^[c-f][A-Za-z0-9_-]{21}$")

    def test_fis_body_and_headers(self):
        request = p.build_fis_create(self.config, self.fid)
        self.assertEqual(request.url, "https://firebaseinstallations.googleapis.com/v1/projects/synthetic-project/installations")
        self.assertEqual(json.loads(gzip.decompress(request.body)), {
            "fid": self.fid, "appId": "1:123:android:abcd", "authVersion": "FIS_v2", "sdkVersion": "a:16.3.5"})
        self.assertEqual(request.headers["X-Android-Cert"], "AB" * 20)
        self.assertEqual(request.headers["X-Android-Package"], "x.app")

    def test_config_rejects_destination_injection_and_mismatched_sender(self):
        for changes in ({"project_id": "evil.example/path"}, {"project_id": "../abc"},
                        {"package": "x.app\r\nInjected: 1"}, {"app_id": "1:456:android:abcd"},
                        {"api_key": "secret\n"}, {"certificate_sha1": "x" * 40}):
            with self.subTest(changes=tuple(changes)), self.assertRaises(p.ProtocolError):
                p.build_fis_create(replace(self.config, **changes), self.fid)

    def test_fis_response(self):
        self.assertEqual(self.installation.expires_seconds, 604800)
        self.assertEqual(self.installation.auth_token, "synthetic-fis-auth-secret")
        numeric = dict(FIXTURE["fis"], name="projects/123/installations/" + self.fid)
        self.assertEqual(p.parse_fis_create(json.dumps(numeric).encode(), self.config, self.fid), self.installation)

    def test_fis_duplicate_and_error_response(self):
        for raw in (b'{"fid":"x","fid":"y"}', b'{"error":{"message":"secret"}}', b'[]', b'{}', b'null'):
            with self.subTest(raw=raw), self.assertRaises(p.ProtocolError):
                p.parse_fis_create(raw, self.config, self.fid)

    def test_fis_identity_and_expiry_fail_closed(self):
        for key, value in (("name", "projects/wrong/installations/" + self.fid),
                           ("fid", "dAAAAAAAAAAAAAAAAAAAAA"), ("refreshToken", "")):
            obj = dict(FIXTURE["fis"], **{key: value})
            with self.subTest(key=key), self.assertRaises(p.ProtocolError):
                p.parse_fis_create(json.dumps(obj).encode(), self.config, self.fid)
        for expiry in ("0s", "-1s", "604800", None, 123):
            obj = dict(FIXTURE["fis"], authToken={"token": "synthetic", "expiresIn": expiry})
            with self.subTest(expiry=expiry), self.assertRaises(p.ProtocolError):
                p.parse_fis_create(json.dumps(obj).encode(), self.config, self.fid)

    def test_registration_mapping_preserves_three_distinct_identities(self):
        request = p.build_android_registration(self.config, self.installation, self.credentials,
                                               gms_version=1, android_sdk=28, target_sdk=28,
                                               device_name="Synthetic", build_id="TEST")
        form = parse_qs(request.body.decode())
        self.assertEqual(request.url, p.REGISTER_URL)
        self.assertEqual(form["sender"], ["123"])
        self.assertEqual(form["X-appid"], [self.fid])
        self.assertEqual(form["device"], [str(self.credentials.android_id)])
        self.assertEqual(form["X-Goog-Firebase-Installations-Auth"], [self.installation.auth_token])
        self.assertEqual(form["X-gmp_app_id"], [self.config.app_id])
        self.assertEqual(form["X-scope"], ["*"])
        self.assertEqual(form["X-subtype"], ["123"])
        self.assertNotIn("X-sender", form)
        self.assertNotIn("refreshToken", form)
        self.assertEqual(request.headers["Authorization"],
                         f"AidLogin {self.credentials.android_id}:{self.credentials.security_token}")

    def test_registration_rejects_missing_issuer_credentials(self):
        for value in (0, -1, 2**64, True):
            with self.subTest(value=value), self.assertRaises(p.ProtocolError):
                p.build_android_registration(self.config, self.installation,
                                             p.CheckinCredentials(1, value), gms_version=1, android_sdk=28,
                                             target_sdk=28, device_name="Synthetic", build_id="TEST")

    def test_registration_response_preserves_equals(self):
        self.assertEqual(p.parse_registration(b"token=synthetic=padding\n").token, "synthetic=padding")
        self.assertFalse(p.parse_registration(b"Error=synthetic-private-detail").accepted)

    def test_registration_ambiguous_or_malformed(self):
        for raw in (b"token=", b"token=a\nError=b", b"token=a\ntoken=b", b"unknown=x", b"\xff"):
            with self.subTest(raw=raw), self.assertRaises(p.ProtocolError):
                p.parse_registration(raw)

    def test_checkin_known_fixed64_values_no_float_or_signed_truncation(self):
        self.assertEqual(self.credentials.android_id, 0x0102030405060708)
        self.assertEqual(self.credentials.security_token, 0x9112131415161718)

    def test_checkin_fresh_mac_profile(self):
        request = p.build_checkin()
        fields = p.decode_fields(request.body)
        self.assertEqual(fields.one(2, 0), 0)
        self.assertEqual(fields.one(13, 1), 0)
        self.assertEqual(fields.one(14, 0), 3)
        checkin = p.decode_fields(fields.one(4, 2))
        self.assertEqual(checkin.one(12, 0), 3)
        chrome = p.decode_fields(checkin.one(13, 2))
        self.assertEqual(chrome.one(1, 0), 2)  # MAC, not Android or Linux
        self.assertEqual(chrome.one(3, 0), 5)  # UNKNOWN channel
        self.assertEqual(chrome.one(2, 2), b"0.1.0")

    def test_checkin_duplicate_wrong_type_and_failure(self):
        valid = bytes.fromhex(FIXTURE["checkin_response_hex"])
        for data in (valid + b"\x39" + b"\x01" * 8, valid.replace(b"\x39", b"\x38", 1),
                     b"\x08\x00" + valid[2:], b"\x08\x01", valid[:-1]):
            with self.subTest(data=data.hex()), self.assertRaises(p.ProtocolError):
                p.parse_checkin(data)

    def test_varint_golden_and_boundaries(self):
        self.assertEqual(p.varint(300), bytes.fromhex("ac02"))
        self.assertEqual(p.varint(2**64 - 1), b"\xff" * 9 + b"\x01")
        for val in (-1, 2**64, True):
            with self.assertRaises(p.ProtocolError):
                p.varint(val)

    def test_protobuf_malformed(self):
        for data in (b"\x00", b"\x0b", b"\x80\x00", b"\x08" + b"\xff" * 10,
                     b"\x12\x04x", b"\x09\x00", b"\x08\x80"):
            with self.subTest(data=data.hex()), self.assertRaises(p.ProtocolError):
                p.decode_fields(data)

    def test_unknown_fields_are_skipped_but_bounded(self):
        raw = bytes.fromhex(FIXTURE["checkin_response_hex"]) + p.field(99, b"synthetic")
        self.assertEqual(p.parse_checkin(raw), self.credentials)
        with self.assertRaises(p.ProtocolError):
            p.decode_fields(b"\x08\x01" * 4097)

    def test_mcs_login_build_uses_issuer_credentials(self):
        frames = p.MCSDecoder().feed(p.build_mcs_login(self.credentials))
        self.assertEqual(frames[0].tag, 2)
        fields = p.decode_fields(frames[0].payload)
        self.assertEqual(fields.one(5, 2), str(self.credentials.security_token).encode())
        self.assertEqual(fields.one(6, 2), b"android-102030405060708")
        self.assertEqual(fields.one(16, 0), 2)
        self.assertEqual(fields.one(14, 0), 1)

    def test_mcs_golden_login_success_and_rejection(self):
        for name, expected in (("mcs_login_success_hex", True), ("mcs_login_rejected_hex", False)):
            decoder = p.MCSDecoder()
            frames = decoder.feed(bytes.fromhex(FIXTURE[name]))
            decoder.finish()
            self.assertEqual(p.parse_mcs_login(frames[0]), expected)

    def test_mcs_every_fragment_boundary(self):
        raw = bytes.fromhex(FIXTURE["mcs_data_hex"])
        for boundary in range(len(raw) + 1):
            decoder = p.MCSDecoder()
            frames = decoder.feed(raw[:boundary]) + decoder.feed(raw[boundary:])
            decoder.finish()
            self.assertEqual(len(frames), 1)
            data = p.parse_android_data(frames[0], sender_id="123", package="x.app")
            self.assertEqual(data.properties, {"foo": "ok"})
            self.assertEqual(data.persistent_id, b"pid-01")

    def test_mcs_coalesced_frames_and_one_byte_chunks(self):
        raw = bytes.fromhex(FIXTURE["mcs_login_success_hex"]) + b"\x00\x00\x01\x00"
        for chunks in ([raw], [bytes([v]) for v in raw]):
            decoder = p.MCSDecoder()
            frames = [f for chunk in chunks for f in decoder.feed(chunk)]
            decoder.finish()
            self.assertEqual([f.tag for f in frames], [3, 0, 1])

    def test_mcs_multi_byte_length_fragmentation(self):
        raw = p.mcs_frame(8, b"x" * 300, first=True)
        for boundary in range(1, 6):
            decoder = p.MCSDecoder()
            frames = decoder.feed(raw[:boundary]) + decoder.feed(raw[boundary:])
            decoder.finish()
            self.assertEqual(frames[0].payload, b"x" * 300)

    def test_mcs_oversize_overlong_bad_version_tag_and_poisoned_state(self):
        for data in (b"\x00", b"\x29\xff\x00", b"\x29\x08" + p.varint(p.LIMIT + 1),
                     b"\x29\x08\x80\x00", b"\x29\x08" + b"\x80" * 5):
            decoder = p.MCSDecoder()
            with self.subTest(data=data.hex()), self.assertRaises(p.ProtocolError):
                decoder.feed(data)
            with self.assertRaises(p.ProtocolError):
                decoder.feed(b"")

    def test_mcs_truncation(self):
        for raw in (b"", b"\x29\x03", b"\x29\x03\x02\x0a"):
            decoder = p.MCSDecoder()
            decoder.feed(raw)
            with self.assertRaises(p.ProtocolError):
                decoder.finish()

    def test_data_rejects_wrong_sender_package_duplicates_and_web_payload(self):
        frame = p.MCSDecoder().feed(bytes.fromhex(FIXTURE["mcs_data_hex"]))[0]
        for sender, package in (("456", "x.app"), ("123", "wrong.app")):
            with self.assertRaises(p.ProtocolError):
                p.parse_android_data(frame, sender_id=sender, package=package)
        for extra in (p.field(7, p.field(1, "foo") + p.field(2, "other")), p.field(21, b"encrypted")):
            with self.assertRaises(p.ProtocolError):
                p.parse_android_data(p.Frame(8, frame.payload + extra), sender_id="123", package="x.app")

    def test_redaction_never_promotes_provider_success_to_enrollment(self):
        report = p.redacted_status(checkin=self.credentials, installation=self.installation,
                                   registration=p.parse_registration(b"token=synthetic-token"), mcs_authenticated=True)
        self.assertTrue(report["mcs_authenticated"])
        for key in ("microsoft_delivery_proven", "microsoft_device_token_validated",
                    "dos_preventer_obtained", "enrollment_completed"):
            self.assertFalse(report[key])
        output = json.dumps(report) + repr(self.installation) + repr(self.credentials)
        output += repr(p.build_fis_create(self.config, self.fid)) + repr(p.Registration("secret-token", True))
        for secret in ("synthetic-refresh-secret", "synthetic-fis-auth-secret", "secret-token", self.fid,
                       str(self.credentials.security_token)):
            self.assertNotIn(secret, output)

    def test_all_response_sizes_bounded(self):
        large = b"x" * (p.LIMIT + 1)
        for parser in (p.parse_registration, p.parse_checkin,
                       lambda b: p.parse_fis_create(b, self.config, self.fid)):
            with self.assertRaises(p.ProtocolError):
                parser(large)

    def test_prepared_probe_is_zero_identity_and_bounded(self):
        plan = p.prepare_checkin_probe()
        self.assertFalse(plan["live_executor_included"])
        self.assertEqual(plan["maximum_http_posts"], 1)
        self.assertEqual(plan["maximum_mcs_connections"], 1)
        self.assertEqual(plan["automatic_retries"], 0)
        self.assertEqual(plan["microsoft_requests"], 0)
        fields = p.decode_fields(bytes.fromhex(plan["request"]["fresh_request_hex"]))
        self.assertEqual(fields.one(2, 0), 0)
        self.assertEqual(fields.one(13, 1), 0)


if __name__ == "__main__":
    unittest.main()
