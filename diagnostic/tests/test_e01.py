"""Synthetic tests only. All real DNS and socket creation are forbidden."""
import contextlib
import io
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlencode
import xml.etree.ElementTree as ET

from diagnostic import e01

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
BASE = "https://mobileappcommunicator.auth.microsoft.com/activate"
CANARY = "SECRET-CANARY-DO-NOT-PRINT"


def qr(code=CANARY, url=BASE, wrapper="phonefactor://activate_account"):
    return wrapper + "?" + urlencode({"code": code, "url": url})


class OfflineTest(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        self.no_dns = patch.object(socket, "getaddrinfo", side_effect=AssertionError("Real DNS forbidden")).start()
        self.no_socket = patch.object(socket, "socket", side_effect=AssertionError("Real sockets forbidden")).start()

    def fixture(self, name="success"):
        return (FIXTURES / (name + ".xml")).read_bytes()

    def cli(self, arguments):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = e01.main(arguments)
        return code, stdout.getvalue(), stderr.getvalue()

    def assertSecretAbsent(self, output):
        for secret in (CANARY, "synthetic@example.invalid", "SYNTHETIC-CONFIRMATION-DO-NOT-USE",
                       "SYNTHETIC-SECRET-DO-NOT-USE", "DO-NOT-LOG-ME", "SYNTHETIC-FAULT-SECRET-DO-NOT-LOG",
                       "SYNTHETIC-PRIVATE-DETAIL", "SYNTHETIC-ROUTE", "SYNTHETIC-SCOPE",
                       "SYNTHETIC-REQUEST-ID-DO-NOT-PRINT"):
            self.assertNotIn(secret, output)


class QRTests(OfflineTest):
    def test_legacy_forms(self):
        for wrapper in ("phonefactor://activate_account", "microsoft-authenticator://activateMfa"):
            with self.subTest(wrapper=wrapper):
                enrollment = e01.parse_qr(qr(wrapper=wrapper))
                self.assertEqual(enrollment.code, CANARY)
                self.assertEqual(enrollment.destination.path, "/activate/PfPaWs.asmx")

    def test_observed_app_link(self):
        for host in e01.APP_LINK_HOSTS:
            uri = qr(wrapper="https://" + host + "/authenticatorApp/activateAccount")
            result = e01.parse_qr(uri + "&accountType=mfa&source=qrCode")
            self.assertEqual(result.link_kind, "app_link")

    def test_every_allowlist_suffix_and_label_boundary(self):
        for domain in e01.SERVICE_DOMAINS:
            for host in (domain, "region." + domain):
                self.assertEqual(e01.validate_destination("https://" + host).domain, domain)
            for host in (domain + ".example.invalid", "evil" + domain):
                with self.assertRaises(e01.DiagnosticError):
                    e01.validate_destination("https://" + host)

    def test_destination_rejects_ambiguous_or_arbitrary_addresses(self):
        host = "mobileappcommunicator.auth.microsoft.com"
        bad = ["http://" + host, "https://example.invalid", "https://127.0.0.1", "https://[::1]",
               "https://" + host + ":444", "https://" + host + ":",
               "https://user@" + host, "https://" + host + "@example.invalid",
               "https://" + host + ".", "https://" + host + "?secret=" + CANARY,
               "https://" + host + "#" + CANARY, "https://" + host + "/../activate",
               "https://" + host + "/%2e%2e/activate", "https://" + host + "/%252e/activate",
               "https://" + host + "/x//y", "https://" + host + "/PfPaWs.asmx",
               "https://" + host + "/x\\y", "https://" + host + "\n",
               "https://" + host + "/x;%00", "https://mіcrosoft.com", " https://" + host]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(e01.DiagnosticError):
                e01.validate_destination(value)

    def test_destinations_canonicalize_only_safe_variations(self):
        for value in (BASE, BASE + "/", BASE.replace("https://", "HTTPS://").replace(".com/", ".COM:443/")):
            self.assertEqual(e01.validate_destination(value).path, "/activate/PfPaWs.asmx")

    def test_bad_qr_formats_and_duplicate_parameters(self):
        for value in (qr() + "&code=OTHER", qr() + "&%63ode=OTHER", qr() + "&url=" + BASE,
                      qr() + "#fragment", qr().replace("phonefactor", "otpauth"),
                      qr().replace("activate_account", "arbitrary"), qr(url="http://example.invalid"),
                      qr() + "&accountType=msa", qr(code=""), qr(code="a\nb"),
                      qr() + "&bad=%XX", qr() + "&bare", qr(code="x") * 10000):
            with self.subTest(value=value[:40]), self.assertRaises(e01.DiagnosticError):
                e01.parse_qr(value)

    def test_app_link_requires_enrollment_shape(self):
        base = qr(wrapper="https://login.microsoftonline.com/authenticatorApp/activateAccount")
        for suffix in ("", "&accountType=msa&source=qrCode", "&accountType=mfa&source=unknown"):
            with self.assertRaises(e01.DiagnosticError):
                e01.parse_qr(base + suffix)

    def test_sensitive_objects_have_no_payload_repr(self):
        enrollment = e01.parse_qr(qr())
        self.assertNotIn(CANARY, repr(enrollment))
        self.assertNotIn("/activate", repr(enrollment.destination))
        self.assertSecretAbsent(repr(e01.parse_response(self.fixture())))


class SerializationTests(OfflineTest):
    def test_wire_contract_from_decompiled_builder(self):
        body = e01.serialize_activate_new(e01.parse_qr(qr(code="A<&>\"'B")), counter=123456)
        self.assertFalse(body.startswith(b"<?xml"))
        root = ET.fromstring(body)
        self.assertEqual(root.tag, "{" + e01.SOAP + "}Envelope")
        self.assertEqual(len(root), 2)
        self.assertEqual(root[0].tag, "{" + e01.SOAP + "}Header")
        self.assertEqual(root[1][0].tag, "{" + e01.PF + "}ActivateNew")
        params = root[1][0][0]
        self.assertEqual(params.tag, "{" + e01.PF + "}activationParams")
        self.assertEqual([c.tag for c in params], ["{" + e01.PF + "}" + s for s in
                         ("ActivationCode", "DeviceToken", "DeviceName", "OathCounter", "Version")])
        self.assertEqual([c.text or "" for c in params], ["A<&>\"'B", "", "Mac E01 diagnostic", "123456", "0.1.0"])
        self.assertIn(b"A&lt;&amp;&gt;", body)

    def test_counter_uses_epoch_thirty_second_steps(self):
        with patch.object(e01.time, "time", return_value=1800000029):
            self.assertIn(b">60000000<", e01.serialize_activate_new(e01.parse_qr(qr())))

    def test_invalid_counters(self):
        for value in (0, -1, True, 1.5, 2**63):
            with self.assertRaises(e01.DiagnosticError):
                e01.serialize_activate_new(e01.parse_qr(qr()), value)

    def test_public_report_never_includes_full_host_path_code_or_body(self):
        enrollment = e01.parse_qr(qr(url="https://" + CANARY.lower() + ".phonefactor.net/" + CANARY))
        output = json.dumps(e01.request_report(enrollment))
        self.assertSecretAbsent(output)
        self.assertNotIn(CANARY.lower(), output)
        self.assertNotIn(BASE, output)


class ResponseTests(OfflineTest):
    def test_rejection_with_request_id_sibling(self):
        parsed = e01.parse_response(self.fixture("rejected-with-request-id"))
        report = e01.report_response(parsed, 200)
        self.assertFalse(parsed.result)
        self.assertTrue(parsed.request_id_present)
        self.assertEqual(report["service_error_code"], 15)
        self.assertTrue(report["oath_token_enabled"])
        self.assertEqual(report["bootstrap_state"], "rejected")
        self.assertTrue(report["field_presence"]["ConfirmationCode"])
        self.assertFalse(report["field_presence"]["OathTokenSecretKey"])
        self.assertFalse(report["enrollment_completed"])
        self.assertFalse(report["device_token_validated"])
        self.assertFalse(report["confirmation_sent"])
        self.assertSecretAbsent(json.dumps(report))
        self.assertNotIn("SYNTHETIC-REQUEST-ID-DO-NOT-PRINT", repr(parsed))
        self.assertNotIn("SYNTHETIC-REQUEST-ID-DO-NOT-PRINT", json.dumps(parsed.fields))

    def test_request_id_can_precede_operation(self):
        root = ET.fromstring(self.fixture("rejected-with-request-id"))
        body = root.find("{" + e01.SOAP + "}Body")
        metadata = body[-1]
        body.remove(metadata); body.insert(0, metadata)
        self.assertTrue(e01.parse_response(ET.tostring(root)).request_id_present)

    def test_success_and_fault_with_request_id(self):
        for name in ("success", "fault"):
            with self.subTest(name=name):
                root = ET.fromstring(self.fixture(name))
                body = root.find("{" + e01.SOAP + "}Body")
                ET.SubElement(body, "{" + e01.SOAP + "}RequestId").text = "SYNTHETIC-REQUEST-ID-DO-NOT-PRINT"
                parsed = e01.parse_response(ET.tostring(root))
                self.assertTrue(parsed.request_id_present)
                self.assertEqual(parsed.fault, name == "fault")
                report = e01.report_response(parsed, 200)
                self.assertFalse(report["enrollment_completed"])
                self.assertSecretAbsent(json.dumps(report))

    def test_duplicate_or_mixed_operations_are_rejected(self):
        for extra in (self.fixture(), self.fixture("rejected"), self.fixture("fault")):
            root = ET.fromstring(self.fixture("rejected-with-request-id"))
            body = root.find("{" + e01.SOAP + "}Body")
            other = ET.fromstring(extra).find("{" + e01.SOAP + "}Body")[0]
            body.append(other)
            with self.assertRaises(e01.DiagnosticError): e01.parse_response(ET.tostring(root))
        root = ET.fromstring(self.fixture("fault"))
        body = root.find("{" + e01.SOAP + "}Body")
        body.append(ET.fromstring(self.fixture("fault")).find("{" + e01.SOAP + "}Body")[0])
        with self.assertRaises(e01.DiagnosticError): e01.parse_response(ET.tostring(root))

    def test_unknown_or_wrong_namespace_body_sibling_is_rejected(self):
        for tag in ("RequestId", "{" + e01.PF + "}RequestId", "{https://example.invalid}RequestId",
                    "{" + e01.PF + "}ConfirmActivationResponse", "{" + e01.SOAP + "}Unknown"):
            with self.subTest(tag=tag):
                root = ET.fromstring(self.fixture("rejected-with-request-id"))
                body = root.find("{" + e01.SOAP + "}Body")
                body[-1].tag = tag
                with self.assertRaises(e01.DiagnosticError): e01.parse_response(ET.tostring(root))

    def test_duplicate_or_structured_request_id_is_rejected(self):
        for variant in ("duplicate", "nested", "attribute"):
            root = ET.fromstring(self.fixture("rejected-with-request-id"))
            body = root.find("{" + e01.SOAP + "}Body")
            if variant == "duplicate": ET.SubElement(body, "{" + e01.SOAP + "}RequestId")
            elif variant == "nested": ET.SubElement(body[-1], "{" + e01.PF + "}ActivateNewResponse")
            else: body[-1].set("unexpected", "SYNTHETIC")
            with self.assertRaises(e01.DiagnosticError): e01.parse_response(ET.tostring(root))

    def test_metadata_alone_empty_or_duplicate_body_is_rejected(self):
        for variant in ("metadata_only", "empty", "duplicate_body"):
            root = ET.fromstring(self.fixture("rejected-with-request-id"))
            body = root.find("{" + e01.SOAP + "}Body")
            if variant == "metadata_only": body.remove(body[0])
            elif variant == "empty": body.clear()
            else: ET.SubElement(root, "{" + e01.SOAP + "}Body")
            with self.assertRaises(e01.DiagnosticError): e01.parse_response(ET.tostring(root))

    def test_success_means_only_bootstrap_progress(self):
        parsed = e01.parse_response(self.fixture())
        report = e01.report_response(parsed, 200)
        self.assertTrue(parsed.result)
        self.assertEqual(parsed.fields["OathTokenSecretKey"], "SYNTHETIC-SECRET-DO-NOT-USE")
        self.assertEqual(report["bootstrap_state"], "progress_reported_not_enrolled")
        for field in ("enrollment_completed", "device_token_validated", "confirmation_sent"):
            self.assertFalse(report[field])
        self.assertTrue(report["field_presence"]["OathTokenSecretKey"])
        self.assertTrue(report["oath_token_enabled"])
        self.assertSecretAbsent(json.dumps(report))

    def test_rejection_exposes_only_numeric_error_and_presence(self):
        report = e01.report_response(e01.parse_response(self.fixture("rejected")), 200)
        self.assertEqual(report["service_error_code"], 4242)
        self.assertEqual(report["bootstrap_state"], "rejected")
        self.assertTrue(report["error_description_present"])
        self.assertSecretAbsent(json.dumps(report))

    def test_error_code_that_equals_secret_is_not_reported(self):
        parsed = e01.parse_response(self.fixture("rejected"))
        self.assertIsNone(e01.report_response(parsed, 200, forbidden=("4242",))["service_error_code"])
        self.assertIsNone(e01.report_response(parsed, 200, forbidden=("SECRET-4242-SECRET",))["service_error_code"])

    def test_optional_oath_boolean_is_validated(self):
        self.assertFalse(e01.report_response(e01.parse_response(self.fixture().replace(
            b"<OathTokenEnabled>true", b"<OathTokenEnabled>false")), 200)["oath_token_enabled"])
        self.assertIsNone(e01.report_response(e01.parse_response(self.fixture("rejected")), 200)["oath_token_enabled"])
        with self.assertRaises(e01.DiagnosticError):
            e01.parse_response(self.fixture().replace(b"<OathTokenEnabled>true", b"<OathTokenEnabled>invalid"))

    def test_non_numeric_error_code_is_not_reported(self):
        data = self.fixture("rejected").replace(b"4242", CANARY.encode())
        report = e01.report_response(e01.parse_response(data), 200)
        self.assertIsNone(report["service_error_code"])
        self.assertSecretAbsent(json.dumps(report))

    def test_fault_text_is_withheld(self):
        report = e01.report_response(e01.parse_response(self.fixture("fault")), 200)
        self.assertTrue(report["soap_fault"])
        self.assertEqual(report["bootstrap_state"], "soap_fault")
        self.assertSecretAbsent(json.dumps(report))

    def test_http_failure_cannot_count_as_bootstrap_success(self):
        parsed = e01.parse_response(self.fixture())
        self.assertEqual(e01.report_response(parsed, 500)["bootstrap_state"], "http_error")
        self.assertEqual(e01.report_response(parsed, 307)["bootstrap_state"], "redirect_blocked")

    def test_prefixes_boolean_forms_and_absent_optional_fields(self):
        data = self.fixture().replace(b">true<", b">1<")
        self.assertTrue(e01.parse_response(data).result)
        data = self.fixture("rejected").replace(b">false<", b">0<")
        self.assertFalse(e01.parse_response(data).result)

    def test_duplicate_result_or_secret_is_rejected(self):
        for marker in (b"<ActivateNewResult>true</ActivateNewResult>", b"<OathTokenSecretKey>SYNTHETIC-SECRET-DO-NOT-USE</OathTokenSecretKey>"):
            with self.assertRaises(e01.DiagnosticError):
                e01.parse_response(self.fixture().replace(marker, marker + marker))

    def test_namespace_confusion_wrong_operation_and_missing_result(self):
        for data in (self.fixture().replace(e01.PF.encode(), b"https://example.invalid"),
                     self.fixture().replace(b"ActivateNewResponse", b"ConfirmActivationResponse"),
                     self.fixture().replace(b"true", b"maybe"),
                     self.fixture().replace(b"ActivateNewResult", b"UnknownResult")):
            with self.assertRaises(e01.DiagnosticError):
                e01.parse_response(data)

    def test_unsafe_malformed_oversized_or_deep_xml(self):
        for data in (b"<html>not SOAP</html>", b"<broken", b"<!DOCTYPE a [<!ENTITY x 'secret'>]><a>&x;</a>",
                     b"<?xml version='1.0' encoding='utf-16'?><a/>", b"\xff",
                     b"x" * (e01.MAX_RESPONSE + 1), b"<a>" * 40 + b"</a>" * 40):
            with self.subTest(length=len(data)), self.assertRaises(e01.DiagnosticError):
                e01.parse_response(data)


class StorageAndCLITests(OfflineTest):
    def test_demo_default_and_explicit_are_offline_and_redacted(self):
        for argv in ([], ["demo"]):
            code, out, err = self.cli(argv)
            self.assertEqual(code, 0, err)
            self.assertFalse(json.loads(out)["network_used"])
            self.assertSecretAbsent(out + err)
        self.no_dns.assert_not_called()
        self.no_socket.assert_not_called()

    def test_check_private_qr_file_is_offline(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "input.txt"
            path.write_text(qr()); path.chmod(0o600)
            code, out, err = self.cli(["check", "--qr-file", str(path)])
        self.assertEqual(code, 0, err)
        self.assertFalse(json.loads(out)["network_used"])
        self.assertSecretAbsent(out + err)

    def test_live_requires_flag_before_input_or_network(self):
        with patch.object(e01, "read_enrollment") as read, patch.object(e01, "send_once") as send:
            code, out, err = self.cli(["live"])
            self.assertEqual(code, 2)
            read.assert_not_called(); send.assert_not_called()

    def test_errors_never_echo_unexpected_arguments_or_filenames(self):
        for argv in (["--qr", CANARY], ["check", "--qr-file", CANARY], ["inspect", "--http-status", CANARY]):
            code, out, err = self.cli(argv)
            self.assertNotEqual(code, 0)
            self.assertSecretAbsent(out + err)

    def test_private_input_permissions_symlinks_and_hardlinks(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "input"
            path.write_text(qr()); path.chmod(0o644)
            with self.assertRaises(e01.DiagnosticError): e01.read_private_file(path, e01.MAX_INPUT)
            path.chmod(0o600)
            self.assertEqual(e01.read_private_file(path, e01.MAX_INPUT).decode(), qr())
            link = Path(folder) / "link"
            link.symlink_to(path)
            with self.assertRaises(OSError): e01.read_private_file(link, e01.MAX_INPUT)
            link.unlink(); os.link(path, link)
            with self.assertRaises(e01.DiagnosticError): e01.read_private_file(path, e01.MAX_INPUT)

    def test_hidden_input_never_falls_back_to_echo(self):
        with patch.object(e01.sys.stdin, "isatty", return_value=False):
            with self.assertRaises(e01.DiagnosticError): e01.secret_prompt("Input: ")

    def test_owner_only_storage_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            run = e01.PrivateRun(Path(folder))
            try:
                run.write("response.bin", b"SYNTHETIC")
                with self.assertRaises(FileExistsError): run.write("response.bin", b"OTHER")
                base = Path(folder) / ".secrets" / "e01" / run.run_id
                for path in (base.parent.parent, base.parent, base):
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE((base / "response.bin").stat().st_mode), 0o600)
            finally: run.close()

    def test_insecure_or_symlinked_private_directory_rejected_before_send(self):
        for kind in ("public", "symlink"):
            with tempfile.TemporaryDirectory() as folder, patch.object(e01, "send_once") as send:
                root = Path(folder)
                if kind == "public":
                    (root / ".secrets").mkdir(mode=0o755)
                else:
                    (root / ".secrets").symlink_to(root)
                with self.assertRaises((OSError, e01.DiagnosticError)):
                    e01.run_live(e01.parse_qr(qr()), root)
                send.assert_not_called()

    def test_offline_inspection_is_redacted(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "response.bin"
            path.write_bytes(self.fixture()); path.chmod(0o600)
            code, out, err = self.cli(["inspect", "--response-file", str(path), "--http-status", "200"])
            self.assertEqual(code, 0, err)
            self.assertSecretAbsent(out + err)

    def test_offline_inspection_with_request_id_is_redacted(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "response.bin"
            path.write_bytes(self.fixture("rejected-with-request-id")); path.chmod(0o600)
            code, out, err = self.cli(["inspect", "--response-file", str(path), "--http-status", "200"])
            self.assertEqual(code, 0, err)
            report = json.loads(out)
            self.assertEqual(report["bootstrap_state"], "rejected")
            self.assertEqual(report["service_error_code"], 15)
            self.assertTrue(report["soap_request_id_present"])
            self.assertFalse(report["network_used"])
            self.assertSecretAbsent(out + err)


class TransportTests(OfflineTest):
    def test_simulated_live_result_is_saved_privately_and_only_once(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(e01, "send_once", return_value=(200, self.fixture())) as send:
                report, code = e01.run_live(e01.parse_qr(qr()), Path(folder))
            send.assert_called_once()
            self.assertEqual(code, 0)
            self.assertFalse(report["enrollment_completed"])
            self.assertEqual(report["request_attempt_budget_consumed"], 1)
            base = Path(folder) / ".secrets/e01" / report["private_run_id"]
            self.assertEqual((base / "response.bin").read_bytes(), self.fixture())
            for name in ("attempt.json", "report.json"):
                self.assertSecretAbsent((base / name).read_text())
            self.assertTrue(report["cleanup_required"])

    def test_transport_failure_is_not_retried_and_text_never_logged(self):
        for failure in (TimeoutError(CANARY), OSError(CANARY), e01.DiagnosticError("request_deadline_exceeded")):
            with tempfile.TemporaryDirectory() as folder, patch.object(e01, "send_once", side_effect=failure) as send:
                report, code = e01.run_live(e01.parse_qr(qr()), Path(folder))
                send.assert_called_once()
                self.assertEqual(code, 3)
                self.assertEqual(report["submission_state"], "attempted_outcome_unknown")
                self.assertSecretAbsent(json.dumps(report))

    def test_redirect_is_never_followed(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(e01, "send_once", return_value=(307, b"SECRET")) as send:
            report, code = e01.run_live(e01.parse_qr(qr()), Path(folder))
            send.assert_called_once()
            self.assertEqual(code, 3)
            self.assertEqual(report["bootstrap_state"], "redirect_blocked")

    def test_malformed_and_oversized_response_do_not_become_success(self):
        for body in (CANARY.encode(), b"x" * (e01.MAX_RESPONSE + 1)):
            with tempfile.TemporaryDirectory() as folder, patch.object(e01, "send_once", return_value=(200, body)):
                report, code = e01.run_live(e01.parse_qr(qr()), Path(folder))
                self.assertEqual(code, 3)
                self.assertEqual(report["bootstrap_state"], "unparsed_response")
                self.assertSecretAbsent(json.dumps(report))

    def test_post_headers_limit_tls_and_one_request(self):
        conn = Mock()
        conn.getresponse.return_value.status = 302
        conn.getresponse.return_value.read.return_value = b""
        with tempfile.TemporaryDirectory() as folder:
            keylog = Path(folder) / "must-not-be-created.log"
            with patch.object(e01, "DirectHTTPSConnection", return_value=conn) as factory, patch.dict(
                os.environ, {"HTTPS_PROXY": "https://example.invalid", "SSLKEYLOGFILE": str(keylog)}
            ):
                status, _ = e01.send_once(e01.parse_qr(qr()), b"synthetic body")
            self.assertFalse(keylog.exists())
        factory.assert_called_once()
        args, kwargs = factory.call_args
        self.assertEqual(args, ("mobileappcommunicator.auth.microsoft.com", 443))
        self.assertEqual(kwargs["context"].verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(kwargs["context"].check_hostname)
        self.assertIsNone(kwargs["context"].keylog_filename)
        conn.set_debuglevel.assert_called_once_with(0)
        conn.request.assert_called_once()
        args, kwargs = conn.request.call_args
        self.assertEqual(args, ("POST", "/activate/PfPaWs.asmx"))
        self.assertEqual(kwargs["headers"]["SOAPAction"], "http://www.phonefactor.com/PfPaWs/ActivateNew")
        self.assertEqual(kwargs["headers"]["Content-Type"], "text/xml; charset=utf-8")
        conn.getresponse.return_value.read.assert_called_once_with(e01.MAX_RESPONSE + 1)
        conn.close.assert_called_once()
        self.assertEqual(status, 302)

    def test_transport_checks_url_again(self):
        enrollment = e01.Enrollment(CANARY, "https://example.invalid", e01.validate_destination(BASE), "manual")
        with patch.object(e01, "DirectHTTPSConnection") as factory:
            with self.assertRaises(e01.DiagnosticError): e01.send_once(enrollment, b"body")
            factory.assert_not_called()

    def test_private_ip_or_mixed_dns_is_rejected(self):
        for ips in (("127.0.0.1",), ("169.254.169.254",), ("10.0.0.1",), ("::1",), ("8.8.8.8", "192.168.1.2")):
            answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443)) for ip in ips]
            with patch.object(socket, "getaddrinfo", return_value=answers):
                conn = e01.DirectHTTPSConnection("test.phonefactor.net", context=ssl.create_default_context())
                with self.assertRaises(e01.DiagnosticError): conn.connect()
        self.no_socket.assert_not_called()

    def test_connect_failure_has_no_second_address_attempt(self):
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443)) for ip in ("8.8.8.8", "1.1.1.1")]
        sock = Mock(); sock.connect.side_effect = TimeoutError()
        with patch.object(socket, "getaddrinfo", return_value=answers), patch.object(socket, "socket", return_value=sock) as factory:
            conn = e01.DirectHTTPSConnection("test.phonefactor.net", context=ssl.create_default_context())
            with self.assertRaises(TimeoutError): conn.connect()
            factory.assert_called_once(); sock.connect.assert_called_once_with(("8.8.8.8", 443))
            sock.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
