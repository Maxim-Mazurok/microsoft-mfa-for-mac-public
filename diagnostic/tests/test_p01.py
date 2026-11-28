"""Synthetic executor checks. All DNS/socket operations are denied or faked."""
from contextlib import redirect_stdout
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
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "diagnostic"))
import p01 as x
import push_protocol as p

FIXTURES = json.loads((ROOT / "diagnostic/fixtures/push-synthetic.json").read_text())
CHECKIN = bytes.fromhex(FIXTURES["checkin_response_hex"])
LOGIN = bytes.fromhex(FIXTURES["mcs_login_success_hex"])


def http(body=CHECKIN, status=200, extra="", length=True):
    header = f"HTTP/1.1 {status} Synthetic\r\n"
    if length:
        header += f"Content-Length: {len(body)}\r\n"
    return (header + extra + "\r\n").encode() + body


class FakeSocket:
    def __init__(self, incoming, fragment=4096, failure=None):
        self.incoming = incoming
        self.fragment = fragment
        self.sent = []
        self.closed = False
        self.failure = failure
        self.address = None

    def settimeout(self, value):
        self.timeout = value

    def connect(self, address):
        self.address = address
        if self.failure:
            raise self.failure

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, count):
        count = min(count, self.fragment)
        result, self.incoming = self.incoming[:count], self.incoming[count:]
        return result

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class ExecutorTests(unittest.TestCase):
    def setUp(self):
        self.no_dns = patch.object(socket, "getaddrinfo", side_effect=AssertionError("Real DNS forbidden")).start()
        self.no_socket = patch.object(socket, "socket", side_effect=AssertionError("Real sockets forbidden")).start()
        self.addCleanup(patch.stopall)

    def tearDown(self):
        self.no_dns.assert_not_called()
        self.no_socket.assert_not_called()

    def root(self):
        tmp = tempfile.TemporaryDirectory(prefix="p01-offline-", dir=ROOT / "work")
        self.addCleanup(tmp.cleanup)
        return Path(tmp.name)

    def simulate(self, checkin=http(), login=LOGIN, fragment=4096, root=None):
        sockets = [FakeSocket(checkin, fragment), FakeSocket(login, fragment)]
        calls = []

        def connect(kind, deadline, report):
            calls.append(kind)
            report[kind + "_connections_attempted"] += 1
            report[kind + "_tls_verified"] = True
            return sockets[0 if kind == "checkin" else 1]

        root = root or self.root()
        with patch.object(x, "connect_tls", side_effect=connect):
            report = x.run_once(root)
        return report, sockets, calls, root

    def test_success_one_post_one_login_and_private_artifacts(self):
        report, sockets, calls, root = self.simulate()
        self.assertEqual(calls, ["checkin", "mcs"])
        self.assertTrue(report["fresh_credentials_observed"])
        self.assertTrue(report["mcs_accepted"])
        self.assertIsNone(report["error"])
        self.assertEqual(report["checkin_posts_attempted"], 1)
        self.assertEqual(report["mcs_logins_attempted"], 1)
        self.assertTrue(all(s.closed for s in sockets))
        self.assertEqual(len(sockets[0].sent), 1)
        self.assertEqual(len(sockets[1].sent), 1)
        sent = sockets[0].sent[0]
        self.assertTrue(sent.startswith(b"POST /checkin HTTP/1.1\r\n"))
        self.assertEqual(sent.split(b"\r\n\r\n", 1)[1], p.build_checkin().body)
        self.assertNotIn(b"Authorization", sent)
        folder = root / ".secrets/push" / report["run_id"]
        for parent in (root / ".secrets", folder.parent, folder):
            self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o700)
        for file in folder.iterdir():
            self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
        creds = json.loads((folder / "credentials.json").read_text())
        self.assertEqual(int(creds["security_token"]), 0x9112131415161718)
        self.assertEqual((folder / "mcs-response.bin").read_bytes(), LOGIN)
        self.assertEqual((folder / "checkin-response.bin").read_bytes(), http())
        for value in creds.values():
            self.assertNotIn(value, json.dumps(report))
        for key in ("microsoft_delivery_proven", "dos_preventer_obtained", "enrollment_completed"):
            self.assertFalse(report[key])

    def test_persistent_lock_blocks_second_run_before_network(self):
        root = self.root()
        self.simulate(root=root)
        with patch.object(x, "connect_tls") as connect:
            report = x.run_once(root)
        connect.assert_not_called()
        self.assertEqual(report["error"], "p01_attempt_already_reserved_no_retry")

    def test_http_rejection_and_redirect_do_not_start_mcs(self):
        for status in (302, 401, 403, 429, 500):
            with self.subTest(status=status):
                report, sockets, calls, _ = self.simulate(http(b"synthetic-private-error", status,
                                                             "Location: https://example.invalid/secret\r\n"))
                self.assertEqual(calls, ["checkin"])
                self.assertEqual(report["error"], "checkin_http_rejected")
                self.assertEqual(report["checkin_http_status"], status)
                self.assertIsNone(report["mcs_accepted"])
                self.assertNotIn("synthetic-private-error", json.dumps(report))
                self.assertFalse(sockets[1].sent)

    def test_content_encoding_and_ambiguous_framing_rejected(self):
        for extra in ("Content-Encoding: gzip\r\n", "Content-Length: 4\r\n",
                      "Transfer-Encoding: chunked\r\n", "Content-Encoding: identity\r\nContent-Encoding: identity\r\n"):
            report, _, calls, _ = self.simulate(http(extra=extra))
            self.assertEqual(calls, ["checkin"])
            self.assertFalse(report["fresh_credentials_observed"])

    def test_chunked_and_connection_close_responses(self):
        chunked = f"{len(CHECKIN):x}\r\n".encode() + CHECKIN + b"\r\n0\r\n\r\n"
        for raw in (http(CHECKIN, length=False), http(chunked, extra="Transfer-Encoding: chunked\r\n", length=False)):
            report, _, _, _ = self.simulate(raw, fragment=1)
            self.assertTrue(report["mcs_accepted"])

    def test_truncated_http_body_stops_without_retry(self):
        raw = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n" + CHECKIN
        report, _, calls, _ = self.simulate(raw)
        self.assertEqual(report["error"], "truncated_http_body")
        self.assertEqual(calls, ["checkin"])

    def test_invalid_credentials_do_not_start_mcs(self):
        for raw in (b"\x08\x01", CHECKIN + p.field(7, 123, 1), b"\x08\x00" + CHECKIN[2:], b"private-invalid-data"):
            report, _, calls, _ = self.simulate(http(raw))
            self.assertEqual(calls, ["checkin"])
            self.assertFalse(report["fresh_credentials_observed"])
            self.assertEqual(report["error"], "invalid_provider_protocol")

    def test_receive_budget_includes_headers_and_body(self):
        raw = http(b"x" * (p.LIMIT + 100), length=False)
        report, _, calls, root = self.simulate(raw)
        self.assertEqual(report["error"], "response_receive_limit_reached")
        self.assertEqual(report["checkin_received_bytes"], p.LIMIT)
        path = root / ".secrets/push" / report["run_id"] / "checkin-response.bin"
        self.assertEqual(path.stat().st_size, p.LIMIT)
        self.assertEqual(calls, ["checkin"])

    def test_declared_oversized_body_stops_early(self):
        report, _, calls, _ = self.simulate(b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n")
        self.assertEqual(report["error"], "response_body_too_large")
        self.assertEqual(calls, ["checkin"])

    def test_mcs_refusal_redacts_message_and_jid(self):
        error = p.field(1, 7) + p.field(2, "synthetic-secret-error")
        payload = p.field(1, "synthetic-private-id") + p.field(2, "synthetic-private-jid") + p.field(3, error)
        report, _, _, _ = self.simulate(login=p.mcs_frame(3, payload, first=True))
        self.assertTrue(report["fresh_credentials_observed"])
        self.assertFalse(report["mcs_accepted"])
        self.assertEqual(report["mcs_error_code"], 7)
        self.assertEqual(report["error"], "mcs_login_rejected")
        self.assertNotIn("synthetic-", json.dumps(report))

    def test_mcs_stops_at_first_login_without_reading_later_event(self):
        report, sockets, _, _ = self.simulate(login=LOGIN + b"\x00\x00", fragment=1)
        self.assertTrue(report["mcs_accepted"])
        self.assertEqual(sockets[1].incoming, b"\x00\x00")
        self.assertEqual(len(sockets[1].sent), 1)

    def test_mcs_unexpected_event_version_length_and_close(self):
        for raw, expected in ((b"\x29\x08", "unexpected_mcs_event_before_login"),
                              (b"\x01\x03", "unsupported_mcs_version"),
                              (b"\x29\x03" + b"\x80" * 5, "invalid_mcs_frame_length"),
                              (b"\x29\x03" + p.varint(p.LIMIT), "mcs_frame_too_large"),
                              (b"\x29\x03\x05\x01", "mcs_closed_before_login_response")):
            with self.subTest(expected=expected):
                report, sockets, _, _ = self.simulate(login=raw)
                self.assertEqual(report["error"], expected)
                self.assertIsNone(report["mcs_accepted"])
                self.assertTrue(sockets[1].closed)

    def test_deadline_failure_preserves_report_and_no_second_exchange(self):
        root = self.root()
        with patch.object(x, "connect_tls", side_effect=x.ProbeError("overall_deadline_exceeded")) as connect:
            report = x.run_once(root)
        self.assertEqual(connect.call_count, 1)
        self.assertEqual(report["error"], "overall_deadline_exceeded")
        self.assertTrue((root / ".secrets/push" / report["run_id"] / "report.json").exists())

    def test_deadline_covers_dns_and_restores_alarm(self):
        old_handler = signal.getsignal(signal.SIGALRM)
        with x.Deadline() as deadline:
            self.assertGreater(signal.getitimer(signal.ITIMER_REAL)[0], 0)
            with patch.object(x.time, "monotonic", return_value=deadline.end + 1):
                with self.assertRaisesRegex(x.ProbeError, "overall_deadline_exceeded"):
                    deadline.remaining()
            with self.assertRaisesRegex(x.ProbeError, "overall_deadline_exceeded"):
                deadline.expired(None, None)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0, 0))
        self.assertEqual(signal.getsignal(signal.SIGALRM), old_handler)

    def test_public_dns_and_verified_tls_single_address(self):
        fake = FakeSocket(b"")
        context = Mock(wrap_socket=Mock(return_value=fake))
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 5228))
                     for ip in ("8.8.8.8", "1.1.1.1")]
        report = {"mcs_connections_attempted": 0}
        with patch.object(socket, "getaddrinfo", return_value=addresses) as dns, \
             patch.object(socket, "socket", return_value=fake) as factory, \
             patch.object(x, "tls_context", return_value=context), x.Deadline() as deadline:
            result = x.connect_tls("mcs", deadline, report)
            with self.assertRaisesRegex(x.ProbeError, "connection_budget_exhausted"):
                x.connect_tls("mcs", deadline, report)
        self.assertIs(result, fake)
        dns.assert_called_once_with("mtalk.google.com", 5228, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
        factory.assert_called_once()
        self.assertEqual(fake.address, ("8.8.8.8", 5228))
        context.wrap_socket.assert_called_once_with(fake, server_hostname="mtalk.google.com")

    def test_private_mixed_and_empty_dns_rejected_before_socket(self):
        for ips in ([], ["127.0.0.1"], ["8.8.8.8", "10.0.0.1"], ["169.254.169.254"]):
            answers = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 443)) for ip in ips]
            with patch.object(socket, "getaddrinfo", return_value=answers), x.Deadline() as deadline:
                with self.assertRaises(x.ProbeError):
                    x.connect_tls("checkin", deadline, {"checkin_connections_attempted": 0})

    def test_failed_connect_closes_socket_no_address_fallback(self):
        fake = FakeSocket(b"", failure=ConnectionRefusedError("synthetic-secret-error"))
        answers = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 443)) for ip in ("8.8.8.8", "1.1.1.1")]
        with patch.object(socket, "getaddrinfo", return_value=answers), \
             patch.object(socket, "socket", return_value=fake) as factory, x.Deadline() as deadline:
            with self.assertRaises(ConnectionRefusedError):
                x.connect_tls("checkin", deadline, {"checkin_connections_attempted": 0})
        factory.assert_called_once()
        self.assertTrue(fake.closed)

    def test_tls_context_ignores_keylog_environment(self):
        with patch.dict(os.environ, {"SSLKEYLOGFILE": "/nonexistent/synthetic-secret-path"}):
            context = x.tls_context()
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertIsNone(context.keylog_filename)
        self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_certificate_failure_is_not_retried(self):
        fake = FakeSocket(b"")
        context = Mock(wrap_socket=Mock(side_effect=ssl.SSLCertVerificationError("synthetic-private-details")))
        answers = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443))]
        root = self.root()
        with patch.object(socket, "getaddrinfo", return_value=answers), \
             patch.object(socket, "socket", return_value=fake) as factory, \
             patch.object(x, "tls_context", return_value=context):
            report = x.run_once(root)
        factory.assert_called_once()
        self.assertEqual(report["error"], "tls_certificate_verification_failed")
        self.assertEqual(report["checkin_posts_attempted"], 0)
        self.assertEqual(report["mcs_connections_attempted"], 0)
        self.assertNotIn("synthetic-private-details", json.dumps(report))

    def test_storage_symlink_and_insecure_directory_fail_before_network(self):
        for scenario in ("private_permissions", "private_symlink", "ancestor_symlink", "ancestor_permissions"):
            root = self.root()
            if scenario == "private_permissions":
                (root / ".secrets").mkdir(mode=0o755)
            elif scenario == "private_symlink":
                (root / ".secrets").symlink_to(self.root(), target_is_directory=True)
            elif scenario == "ancestor_symlink":
                link = self.root() / "link"
                link.symlink_to(root, target_is_directory=True)
                root = link
            else:
                root.chmod(0o777)
            with patch.object(x, "connect_tls") as connect:
                report = x.run_once(root)
            connect.assert_not_called()
            self.assertIsNotNone(report["error"])

    def test_file_overwrite_and_unapproved_name_rejected(self):
        run = x.PrivateRun(self.root())
        self.addCleanup(run.close)
        run.write("attempt.json", b"{}")
        with self.assertRaises(FileExistsError):
            run.write("attempt.json", b"{}")
        with self.assertRaises(x.ProbeError):
            run.write("../leak", b"synthetic")

    def test_cli_offline_default_and_explicit_live_gate(self):
        for argv in ([], ["prepare"], ["live"], ["live", "--one-attempt", "synthetic-secret"], ["--url", "secret"]):
            output = io.StringIO()
            with patch.object(x, "run_once") as run, redirect_stdout(output):
                code = x.main(argv)
            run.assert_not_called()
            self.assertNotIn("synthetic-secret", output.getvalue())
            self.assertEqual(code, 0 if argv in ([], ["prepare"]) else 2)

    def test_cli_suppresses_core_dumps_before_live_and_redacts_exceptions(self):
        output = io.StringIO()
        with patch.object(x.resource, "setrlimit") as limit, \
             patch.object(x, "run_once", side_effect=RuntimeError("synthetic-secret")), redirect_stdout(output):
            code = x.main(["live", "--one-attempt"])
        limit.assert_called_once_with(x.resource.RLIMIT_CORE, (0, 0))
        self.assertEqual(code, 1)
        self.assertNotIn("synthetic-secret", output.getvalue())


if __name__ == "__main__":
    unittest.main()
