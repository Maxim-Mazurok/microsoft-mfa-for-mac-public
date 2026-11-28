"""Synthetic P02 executor checks. Never read real credentials or use real DNS/TLS."""
from contextlib import redirect_stdout
from dataclasses import replace
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "diagnostic"))
import p02 as x
import push_protocol as p
from test_p01 import FakeSocket, http, LOGIN

FID = "cAAAAAAAAAAAAAAAAAAAAA"
NONCE = "1234567890abcdef" * 2
CREDS = {"android_id": "123456789012345", "security_token": "987654321098765"}
TOKEN = "synthetic-oauth-secret"
REG = "synthetic-registration-secret"
FIS_AUTH = "synthetic-fis-auth-secret"
FIS_REFRESH = "synthetic-fis-refresh-secret"
PROJECT_ID = "synthetic-p02-project"
SENDER_ID = "123"
APPLICATION_ID = "1:123:android:abcd"
CONFIG = {"owned_project_confirmed": True, "project_id": PROJECT_ID, "sender_id": SENDER_ID,
          "app_id": APPLICATION_ID, "api_key": "synthetic-api-key", "certificate_sha1": hashlib.sha1(b"synthetic-cert").hexdigest()}
FIS = json.dumps({"fid": FID, "name": f"projects/{PROJECT_ID}/installations/{FID}",
                  "refreshToken": FIS_REFRESH, "authToken": {"token": FIS_AUTH, "expiresIn": "3600s"}}).encode()
SEND = json.dumps({"name": f"projects/{PROJECT_ID}/messages/synthetic-message"}).encode()


def data(sender=SENDER_ID, package=x.prep.PACKAGE, nonce=NONCE, kind="native-mac-control"):
    body = p.field(3, sender) + p.field(5, package) + p.field(9, "synthetic-persistent-id")
    for key, value in (("p02_kind", kind), ("p02_nonce", nonce)):
        body += p.field(7, p.field(1, key) + p.field(2, value))
    return p.mcs_frame(8, body)


def iq(extension=12, content=b""):
    return p.mcs_frame(7, p.field(2, 1) + p.field(3, "")
                       + p.field(7, p.field(1, extension) + p.field(2, content)))


class P02Tests(unittest.TestCase):
    def setUp(self):
        self.no_dns = patch.object(socket, "getaddrinfo", side_effect=AssertionError("Real DNS forbidden")).start()
        self.no_socket = patch.object(socket, "socket", side_effect=AssertionError("Real sockets forbidden")).start()
        self.addCleanup(patch.stopall)

    def tearDown(self):
        self.no_dns.assert_not_called()
        self.no_socket.assert_not_called()

    def root(self):
        tmp = tempfile.TemporaryDirectory(prefix="p02-offline-", dir=ROOT / "work")
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for name in (".secrets", ".secrets/push", ".secrets/push/p02-setup", ".secrets/push/" + "a" * 32):
            (root / name).mkdir(mode=0o700)
        def write(name, value):
            path = root / ".secrets/push" / name
            path.write_bytes(value if isinstance(value, bytes) else x.json_bytes(value))
            path.chmod(0o600)
        write("p01-attempt.lock", {"run_id": "a" * 32})
        write("a" * 32 + "/credentials.json", CREDS)
        write("a" * 32 + "/report.json", {"experiment": "P01", "run_id": "a" * 32,
              "fresh_credentials_observed": True, "mcs_accepted": True, "checkin_posts_attempted": 1})
        write("p02-setup/config.json", CONFIG)
        write("p02-setup/probe.der", b"synthetic-cert")
        write("p02-setup/sender-token.json", {"access_token": TOKEN, "issued_at": time.time() - 1,
              "expires_at": time.time() + 599 - 1, "service_account": f"p02-sender@{PROJECT_ID}.iam.gserviceaccount.com",
              "project_id": PROJECT_ID})
        return root

    def simulate(self, *, fis=http(FIS), registration=http(b"token=" + REG.encode()),
                 login=LOGIN, tail=None, send=http(SEND), fragment=4096, root=None, failure=None):
        sockets = {"fis": FakeSocket(fis, fragment), "register3": FakeSocket(registration, fragment),
                   "mcs": FakeSocket(login + (iq() + data() if tail is None else tail), fragment),
                   "send": FakeSocket(send, fragment)}
        calls = []
        def connect(kind, deadline, report):
            calls.append(kind)
            self.assertEqual(report[kind + "_connections_attempted"], 0)
            report[kind + "_connections_attempted"] = 1
            if failure:
                raise failure
            report[kind + "_tls_verified"] = True
            return sockets[kind]
        root = root or self.root()
        with patch.object(x, "connect_tls", side_effect=connect), patch.object(p, "new_fid", return_value=FID), \
             patch.object(x.secrets, "token_hex", return_value=NONCE):
            report = x.run_once(root)
        return report, sockets, calls, root

    def test_success_exact_counts_serialization_delivery_and_private_files(self):
        report, sockets, calls, root = self.simulate(fragment=1)
        self.assertEqual(calls, ["fis", "register3", "mcs", "send"])
        self.assertIsNone(report["error"])
        self.assertTrue(report["nonce_delivered"])
        self.assertTrue(report["sender_package_kind_nonce_matched"])
        self.assertTrue(report["send_accepted"])
        self.assertEqual(report["housekeeping"]["selective_ack"], 1)
        self.assertEqual(report["http_posts_attempted"], 3)
        self.assertEqual(report["mcs_logins_attempted"], 1)
        self.assertEqual(report["new_google_checkins"], 0)
        self.assertTrue(all(s.closed and len(s.sent) == 1 for s in sockets.values()))
        fis = json.loads(gzip.decompress(sockets["fis"].sent[0].split(b"\r\n\r\n", 1)[1]))
        self.assertEqual(fis["appId"], APPLICATION_ID)
        self.assertEqual(fis["fid"], FID)
        register = parse_qs(sockets["register3"].sent[0].split(b"\r\n\r\n", 1)[1].decode())
        self.assertEqual(register["device"], [CREDS["android_id"]])
        self.assertEqual(register["X-Goog-Firebase-Installations-Auth"], [FIS_AUTH])
        self.assertEqual(register["sender"], [SENDER_ID])
        self.assertEqual(register["X-gmsv"], ["1"])
        message = json.loads(sockets["send"].sent[0].split(b"\r\n\r\n", 1)[1])["message"]
        self.assertEqual(message["token"], REG)
        self.assertEqual(message["data"]["p02_nonce"], NONCE)
        self.assertEqual(message["android"]["ttl"], "60s")
        lock = json.loads((root / ".secrets/push/p02-attempt.lock").read_text())
        folder = root / ".secrets/push" / lock["run_id"]
        self.assertEqual(stat.S_IMODE(folder.stat().st_mode), 0o700)
        for path in folder.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual((folder / "mcs-response.bin").read_bytes(), LOGIN + iq() + data())
        self.assertNotIn("run_id", report)
        for secret in [*CREDS.values(), TOKEN, REG, FIS_AUTH, FIS_REFRESH, NONCE, CONFIG["api_key"], FID]:
            self.assertNotIn(secret, json.dumps(report))
        for key in ("microsoft_delivery_proven", "dos_preventer_obtained", "enrollment_completed"):
            self.assertFalse(report[key])

    def test_repeat_blocked_before_network_preserves_p01(self):
        report, _, _, root = self.simulate()
        before = (root / ".secrets/push/p01-attempt.lock").read_bytes()
        report, _, calls, _ = self.simulate(root=root)
        self.assertEqual(calls, [])
        self.assertEqual(report["error"], "p02_attempt_already_reserved_no_retry")
        self.assertEqual(before, (root / ".secrets/push/p01-attempt.lock").read_bytes())

    def test_replayed_control_requires_configured_sender_and_control_kind(self):
        root = self.root()
        for sender, kind, accepted in ((SENDER_ID, "native-mac-control", True),
                                       ("999", "native-mac-control", False),
                                       (SENDER_ID, "unexpected", False)):
            decoder = p.MCSDecoder()
            frame = decoder.feed(b"\x29" + data(sender=sender, kind=kind))[0]
            if accepted:
                self.assertTrue(x.is_prior_control_message(frame, root))
            else:
                with self.assertRaises((x.ProbeError, p.ProtocolError)):
                    x.is_prior_control_message(frame, root)

    def test_other_package_does_not_read_own_project_configuration(self):
        decoder = p.MCSDecoder()
        frame = decoder.feed(b"\x29" + data(package="com.azure.authenticator"))[0]
        with patch.object(x.prep, "private_config") as read_configuration:
            self.assertFalse(x.is_prior_control_message(frame))
        read_configuration.assert_not_called()

    def test_fis_rejection_redirect_and_malformed_stop_without_registering(self):
        for raw in (http(b"secret-error", 302, "Location: https://evil.invalid/\r\n"),
                    http(b'{"error":{"status":"PERMISSION_DENIED","message":"secret-error"}}', 403),
                    http(b"secret-error"), http(FIS.replace(FID.encode(), b"dBBBBBBBBBBBBBBBBBBBBB"))):
            report, _, calls, _ = self.simulate(fis=raw)
            self.assertEqual(calls, ["fis"])
            self.assertFalse(report["registration_token_present"])
            self.assertNotIn("secret-error", json.dumps(report))

    def test_registration_error_stops_before_mcs_and_send(self):
        for status in (200, 401, 503):
            report, _, calls, _ = self.simulate(registration=http(b"Error=AUTHENTICATION_FAILED", status))
            self.assertEqual(calls, ["fis", "register3"])
            self.assertEqual(report["register3_provider_error"], "AUTHENTICATION_FAILED")
            self.assertFalse(report["registration_token_present"])
            self.assertEqual(report["http_posts_attempted"], 2)

    def test_registration_ambiguous_or_unknown_error_not_reflected(self):
        for body in (b"Error=private-secret", b"token=one\ntoken=two", b"unexpected-private-secret"):
            report, _, calls, _ = self.simulate(registration=http(body))
            self.assertEqual(calls, ["fis", "register3"])
            self.assertNotIn("private-secret", json.dumps(report))

    def test_login_rejection_or_data_before_login_stops_before_send(self):
        rejected = p.mcs_frame(3, p.field(1, "") + p.field(3, p.field(1, 1)), first=True)
        for login in (rejected, b"\x29" + data(), LOGIN[:2]):
            report, _, calls, _ = self.simulate(login=login, tail=b"")
            self.assertEqual(calls, ["fis", "register3", "mcs"])
            self.assertFalse(report["send_accepted"])

    def test_send_rejected_or_wrong_project_never_claims_delivery(self):
        for send in (http(b'{"error":{"status":"PERMISSION_DENIED","message":"private-secret"}}', 403),
                     http(b'{"name":"projects/another/messages/x"}'), http(b"{}")):
            report, _, calls, _ = self.simulate(send=send)
            self.assertEqual(len(calls), 4)
            self.assertFalse(report["nonce_delivered"])
            self.assertNotIn("private-secret", json.dumps(report))

    def test_send_accepted_is_not_delivery(self):
        for tail in (b"", p.mcs_frame(4, b"")):
            report, _, _, _ = self.simulate(tail=tail)
            self.assertTrue(report["send_accepted"])
            self.assertFalse(report["nonce_delivered"])
            self.assertIn(report["error"], ("mcs_connection_closed", "mcs_server_closed_stream"))

    def test_wrong_sender_package_kind_nonce_rejected(self):
        for tail, expected in ((data(sender="999"), "unexpected_sender"),
                               (data(package="wrong.app"), "unexpected_package"),
                               (data(kind="wrong"), "unexpected_payload_kind"),
                               (data(nonce="0" * 32), "unexpected_payload_nonce")):
            report, _, _, _ = self.simulate(tail=tail)
            self.assertFalse(report["nonce_delivered"])
            self.assertEqual(report["error"], expected)

    def test_housekeeping_known_only_with_frame_count_limit(self):
        tail = p.mcs_frame(0, b"") + p.mcs_frame(1, b"") + iq(13) + iq(12, p.field(1, "synthetic")) + data()
        report, sockets, _, _ = self.simulate(tail=tail)
        self.assertTrue(report["nonce_delivered"])
        self.assertTrue(all(v == 1 for v in report["housekeeping"].values()))
        self.assertEqual(len(sockets["mcs"].sent), 1)
        for tail in (iq(99), iq(13, p.field(1, "invalid")), p.mcs_frame(0, p.field(1, "wrong-wire")),
                     p.mcs_frame(9, b""), iq() * 128):
            report, _, _, _ = self.simulate(tail=tail)
            self.assertFalse(report["nonce_delivered"])
            self.assertIsNotNone(report["error"])

    def test_receive_timeout_is_explicit_and_bounded(self):
        with patch.object(x, "read_frame", side_effect=[p.Frame(3, p.field(1, "")), socket.timeout()]):
            report, _, _, _ = self.simulate()
        self.assertEqual(report["error"], "nonce_delivery_not_observed_within_window")
        self.assertTrue(report["send_accepted"])
        deadline = Mock(); deadline.remaining.return_value = 8
        with patch.object(x.time, "monotonic", return_value=100):
            window = x.ReceiveWindow(deadline)
            self.assertEqual(window.remaining(), 8)
        with patch.object(x.time, "monotonic", return_value=131), self.assertRaises(x.ProbeError):
            window.remaining()

    def test_http_ambiguity_truncation_limit_and_chunking(self):
        for raw in (http(FIS, extra="Content-Length: 1\r\n"), http(FIS, extra="Content-Encoding: gzip\r\n"),
                    http(FIS, extra="Transfer-Encoding: chunked\r\n"), http(FIS)[:-10],
                    b"HTTP/1.1 200 OK\r\nContent-Length: 262144\r\n\r\n"):
            report, _, calls, _ = self.simulate(fis=raw)
            self.assertEqual(calls, ["fis"])
            self.assertIsNotNone(report["error"])
        chunk = f"{len(FIS):x}\r\n".encode() + FIS + b"\r\n0\r\n\r\n"
        report, _, _, _ = self.simulate(fis=http(chunk, extra="Transfer-Encoding: chunked\r\n", length=False))
        self.assertTrue(report["nonce_delivered"])

    def test_mcs_large_noncanonical_frames_rejected(self):
        for tail in (b"\x08" + p.varint(p.LIMIT), b"\x08\x80\x00", b"\x08\x80\x80\x80\x80\x80"):
            report, _, _, _ = self.simulate(tail=tail)
            self.assertFalse(report["nonce_delivered"])
            self.assertIsNotNone(report["error"])

    def test_tls_failure_does_not_retry_or_send(self):
        report, _, calls, _ = self.simulate(failure=ssl.SSLCertVerificationError("synthetic-secret"))
        self.assertEqual(calls, ["fis"])
        self.assertEqual(report["http_posts_attempted"], 0)
        self.assertEqual(report["error"], "tls_certificate_verification_failed")

    def test_partial_write_consumes_post_and_persistent_attempt(self):
        with patch.object(FakeSocket, "sendall", side_effect=ConnectionResetError("synthetic-secret")):
            report, _, calls, root = self.simulate()
        self.assertEqual(calls, ["fis"])
        self.assertEqual(report["http_posts_attempted"], 1)
        self.assertEqual(report["error"], "connection_reset")
        self.assertTrue((root / ".secrets/push/p02-attempt.lock").exists())

    def test_deadline_is_sixty_seconds_including_dns_and_restores_handler(self):
        previous = signal.getsignal(signal.SIGALRM)
        with x.Deadline() as deadline:
            self.assertGreater(signal.getitimer(signal.ITIMER_REAL)[0], 59)
            self.assertLessEqual(deadline.remaining(), 60)
            with self.assertRaises(x.ProbeError):
                x.Deadline.expired(None, None)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertEqual(signal.getsignal(signal.SIGALRM), previous)
        with patch.object(socket, "getaddrinfo", side_effect=x.ProbeError("overall_deadline_exceeded")):
            with self.assertRaises(x.ProbeError):
                x.connect_tls("fis", Mock(), x.new_report())

    def test_receive_cap_counts_headers_and_chunk_framing(self):
        raw = http(b"private" * 100, extra="Padding: " + "x" * 700 + "\r\n", length=False)
        # Builders are smaller than this reduced cap; reply headers cross it.
        with patch.object(p, "LIMIT", 650):
            report, _, calls, _ = self.simulate(fis=raw)
        self.assertEqual(calls, ["fis"])
        self.assertEqual(report["fis_received_bytes"], 650)
        self.assertEqual(report["error"], "response_receive_limit_reached")

    def test_private_output_refuses_overwrite_traversal_and_symlink(self):
        root = self.root(); run = x.PrivateRun(root); self.addCleanup(run.close)
        run.write("probe.json", b"{}")
        with self.assertRaises(FileExistsError):
            run.write("probe.json", b"{}")
        with self.assertRaises(x.ProbeError):
            run.write("../unsafe", b"{}")
        folder = root / ".secrets/push" / run.run_id
        (folder / "report.json").symlink_to(folder / "probe.json")
        with self.assertRaises(FileExistsError):
            run.write("report.json", b"{}")

    def test_p01_provenance_and_credentials_required(self):
        for name, change in (("report.json", lambda v: v.update(mcs_accepted=False)),
                             ("credentials.json", lambda v: v.update(android_id="0")),
                             ("credentials.json", lambda v: v.update(security_token="18446744073709551616"))):
            root = self.root(); path = root / ".secrets/push" / ("a" * 32) / name
            obj = json.loads(path.read_text()); change(obj); path.write_bytes(x.json_bytes(obj))
            report, _, calls, _ = self.simulate(root=root)
            self.assertEqual(calls, [])
            self.assertIsNotNone(report["error"])

    def test_invalid_private_inputs_do_not_consume_attempt(self):
        for name, change in (("config.json", lambda v: v.update(project_id="wrong-project")),
                             ("config.json", lambda v: v.update(owned_project_confirmed=False)),
                             ("config.json", lambda v: v.update(certificate_sha1="a" * 40)),
                             ("sender-token.json", lambda v: v.update(expires_at=time.time() + 10)),
                             ("sender-token.json", lambda v: v.update(service_account="wrong-account"))):
            root = self.root(); path = root / ".secrets/push/p02-setup" / name
            obj = json.loads(path.read_text()); change(obj); path.write_bytes(x.json_bytes(obj))
            report, _, calls, _ = self.simulate(root=root)
            self.assertEqual(calls, [])
            self.assertFalse((root / ".secrets/push/p02-attempt.lock").exists())
            self.assertIsNotNone(report["error"])

    def test_symlink_and_world_readable_inputs_rejected(self):
        for symlink in (False, True):
            root = self.root(); path = root / ".secrets/push/p02-setup/config.json"
            if symlink:
                target = path.with_name("config.other"); path.rename(target); path.symlink_to(target)
            else:
                path.chmod(0o644)
            report, _, calls, _ = self.simulate(root=root)
            self.assertEqual(calls, [])
            self.assertIsNotNone(report["error"])

    def test_request_destination_and_header_injection_rejected_before_dns(self):
        config = x.prep.config_from_json(x.json_bytes(CONFIG))
        request = p.build_fis_create(config, FID)
        for bad in (replace(request, url="https://evil.invalid/"),
                    replace(request, url=request.url + "?other=1"),
                    replace(request, headers={"Authorization": "x\r\nInjected: yes"}),
                    replace(request, headers={"Host": "evil.invalid"})):
            with self.assertRaises(x.ProbeError):
                x.post("fis", bad, config, None, Mock(), x.new_report())

    def test_connection_allowlist_public_dns_first_address_and_no_retry(self):
        report = x.new_report(); deadline = Mock(); deadline.remaining.return_value = 10
        with self.assertRaises(x.ProbeError):
            x.connect_tls("checkin", deadline, report)
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443)),
                     (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.4.4", 443))]
        sock = FakeSocket(b"", failure=ConnectionRefusedError())
        with patch.object(socket, "getaddrinfo", return_value=addresses) as dns, \
             patch.object(socket, "socket", return_value=sock) as socket_factory:
            with self.assertRaises(ConnectionRefusedError):
                x.connect_tls("fis", deadline, report)
            self.assertEqual(sock.address, addresses[0][4]); self.assertTrue(sock.closed)
            socket_factory.assert_called_once()
            with self.assertRaises(x.ProbeError):
                x.connect_tls("fis", deadline, report)
            dns.assert_called_once()
        addresses[1] = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443))
        with patch.object(socket, "getaddrinfo", return_value=addresses):
            with self.assertRaises(x.ProbeError):
                x.connect_tls("fis", deadline, x.new_report())

    def test_budgets_exhausted_before_connect_and_login_send(self):
        config = x.prep.config_from_json(x.json_bytes(CONFIG)); report = x.new_report()
        report["http_posts_attempted"] = 3
        with self.assertRaises(x.ProbeError):
            x.post("fis", p.build_fis_create(config, FID), config, None, Mock(), report)
        report["mcs_logins_attempted"] = 1; sock = Mock()
        with self.assertRaises(x.ProbeError):
            x.mcs_login(sock, None, None, Mock(), report)
        sock.sendall.assert_not_called()

    def test_cli_default_gate_and_no_secret_exception_echo(self):
        for args in ([], ["prepare"], ["live"], ["live", "--one-attempt", "secret-argument"]):
            output = io.StringIO()
            with patch.object(x, "run_once") as run, redirect_stdout(output):
                code = x.main(args)
            run.assert_not_called()
            self.assertNotIn("secret-argument", output.getvalue())
            self.assertEqual(code, 0 if args in ([], ["prepare"]) else 2)
        output = io.StringIO()
        with patch.object(x.resource, "setrlimit") as limit, \
             patch.object(x, "run_once", side_effect=ValueError("secret-exception")), redirect_stdout(output):
            self.assertEqual(x.main(["live", "--one-attempt"]), 1)
        limit.assert_called_once_with(x.resource.RLIMIT_CORE, (0, 0))
        self.assertNotIn("secret-exception", output.getvalue())


if __name__ == "__main__":
    unittest.main()
