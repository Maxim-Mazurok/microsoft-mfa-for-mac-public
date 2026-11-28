"""Synthetic only. No actual credentials, provider traffic, or Microsoft requests."""
import asyncio
from contextlib import asynccontextmanager, contextmanager
import io
import json
from pathlib import Path
import socket
import ssl
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import e01
import e02 as x
import enrollment_protocol as ep
import push_protocol as p

BASE = "https://synthetic.mobileappcommunicator.auth.microsoft.com"
ACCOUNT = "synthetic@example.invalid"
TOKEN = "synthetic-e02-fcm-token"
CODE = "synthetic-fresh-activation-code"
ENROLLMENT = e01.Enrollment(CODE, BASE, ep.destination(BASE), "manual")
PROPERTIES = {"type": "validate", "source": "SAS", "guid": "synthetic-guid", "url": BASE[8:]}
CREDS = p.CheckinCredentials(123456, 654321)


def soap(operation, fields, sibling=""):
    inner = "".join(f"<p:{k}>{v}</p:{k}>" for k, v in fields.items())
    return (f'<s:Envelope xmlns:s="{e01.SOAP}" xmlns:p="{e01.PF}"><s:Body>'
            f'<p:{operation}Response>{inner}</p:{operation}Response>{sibling}</s:Body></s:Envelope>').encode()


ACTIVATION = soap("ActivateNew", {"ActivateNewResult": "true", "Username": ACCOUNT,
    "AzureObjectId": "synthetic-object", "TenantId": "synthetic-tenant", "ConfirmationCode": "synthetic-confirmation",
    "OathTokenSecretKey": "synthetic-oath-key", "OathTokenEnabled": "true"}, "<s:RequestId>synthetic-id</s:RequestId>")
VALIDATION = (b'<pfpMessage version="1.6"><response><phoneAppValidateDeviceTokenResponse>'
    b'<groupKey>synthetic-group</groupKey><accountName>synthetic-name</accountName>'
    b'<dosPreventer>synthetic-dos</dosPreventer></phoneAppValidateDeviceTokenResponse></response></pfpMessage>')
CONFIRMATION = soap("ConfirmActivation", {"ConfirmActivationResult": "true", "phoneAppDetailId": "synthetic-method"})
STATUS = b'<status disposition="success"><error-id>0</error-id><message lang="en"/></status>'


def http(body, status=200):
    return f"HTTP/1.1 {status} Synthetic\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body


def data(properties=PROPERTIES, sender=x.p03.SENDER, package=x.p03.PACKAGE):
    payload = p.field(3, sender) + p.field(5, package)
    for k, v in properties.items():
        payload += p.field(7, p.field(1, k) + p.field(2, v))
    return p.mcs_frame(8, payload)


class Run:
    def __init__(self): self.files = {}
    @contextmanager
    def capture(self, name):
        if name in self.files: raise AssertionError("duplicate capture")
        stream = io.BytesIO()
        try: yield stream
        finally: self.files[name] = stream.getvalue()
    def write(self, name, value):
        if name in self.files: raise AssertionError("duplicate write")
        self.files[name] = value


class Codecs(unittest.TestCase):
    def test_activation_fields_and_escaping(self):
        request = ep.activate(ENROLLMENT, TOKEN + "<&", 1234)
        root = ET.fromstring(request.body)
        fields = root.find(f".//{{{e01.PF}}}activationParams")
        self.assertEqual([n.tag.rsplit("}", 1)[-1] for n in fields],
                         ["ActivationCode", "DeviceToken", "DeviceName", "OathCounter", "Version"])
        self.assertEqual(fields[1].text, TOKEN + "<&")
        self.assertEqual(fields[3].text, "1234")
        self.assertNotIn(TOKEN, repr(request))
        with self.assertRaises(Exception): ep.activate(ENROLLMENT, "")

    def test_validation_xml_empty_accounts_and_hash(self):
        notice = ep.validation_notification(PROPERTIES)
        request = ep.validate(notice, TOKEN, "11111111-1111-4111-8111-111111111111")
        root = ET.fromstring(request.body)
        self.assertEqual(root.tag, "pfpMessage"); self.assertEqual(root.attrib, {"version": "1.6"})
        self.assertEqual(root.find("request").get("async"), "0")
        body = root.find("request/phoneAppValidateDeviceTokenRequest")
        self.assertEqual(body.findtext("phoneAppContext/needDosPreventer"), "yes")
        self.assertEqual(body.findtext("validationResult"), "yes")
        self.assertEqual(len(body.find("accounts")), 0)
        self.assertEqual(request.url, BASE + "/pad")
        self.assertEqual(request.headers["x-ms-mac-device-token"], ep.hashlib.sha256(TOKEN.encode()).hexdigest())

    def test_notification_rejects_auth_v2_foreign_source_and_destination(self):
        for changes in ({"type": "auth"}, {"type": "other"}, {"source": "foreign"},
                        {"deviceTokenChangeVersion": "V2"}, {"guid": ""}, {"url": "evil.invalid"},
                        {"url": BASE}, {"url": BASE[8:] + "/path"}, {"url": BASE[8:] + ":443"},
                        {"url": BASE[8:] + ".evil.invalid"}):
            with self.subTest(changes=changes), self.assertRaises(Exception):
                ep.validation_notification({**PROPERTIES, **changes})

    def test_response_strictness_and_soap_metadata(self):
        self.assertTrue(ep.activation_response(ACTIVATION).result)
        self.assertEqual(ep.confirmation_response(CONFIRMATION)["phoneAppDetailId"], "synthetic-method")
        self.assertEqual(ep.validation_response(VALIDATION)["dosPreventer"], "synthetic-dos")
        for raw in (ACTIVATION.replace(b"<s:RequestId>", b"<p:RequestId>"),
                    ACTIVATION.replace(b"</s:Body>", b"<p:ActivateNewResponse/></s:Body>"),
                    ACTIVATION.replace(b"<p:Username>", b"<s:Username>").replace(b"</p:Username>", b"</s:Username>"),
                    ACTIVATION.replace(b"</p:Username>", b"</p:Username><p:Username>duplicate</p:Username>")):
            with self.assertRaises(Exception): ep.activation_response(raw)
        for raw in (VALIDATION.replace(b"</response>", b"<phoneAppValidateDeviceTokenResponse/></response>"),
                    VALIDATION.replace(b"<dosPreventer>", b"<dosPreventer x='y'>"),
                    VALIDATION.replace(b"synthetic-dos", b""),
                    VALIDATION.replace(b"phoneAppValidateDeviceTokenResponse", b"authenticationResponse"),
                    b'<!DOCTYPE x [<!ENTITY a "bad">]>' + VALIDATION):
            with self.assertRaises(Exception): ep.validation_response(raw)
        with self.assertRaises(Exception): ep.confirmation_response(ACTIVATION)

    def test_routed_notification_preserves_query_and_literal_suffix(self):
        service = BASE[8:] + "/mac/SyntheticService.svc/?dc=synthetic-region&handler=route01"
        notice = ep.validation_notification({**PROPERTIES, "url": service})
        request = ep.validate(notice, TOKEN)
        self.assertEqual(request.url, "https://" + service + "/pad")
        host, wire = x.request_wire("validate", request, ENROLLMENT)
        self.assertEqual(host, BASE[8:])
        self.assertTrue(wire.startswith(b"POST /mac/SyntheticService.svc/?dc=synthetic-region&handler=route01/pad HTTP/1.1\r\n"))
        for bad in (service + "#bad", service + "&dc=duplicate", service + "&key=%0d%0a",
                    service.replace("/mac/SyntheticService.svc", "/mac/.."),
                    service.replace("/mac/", "/other/"), service.replace(".com/", ".com.evil.invalid/")):
            with self.assertRaises(Exception): ep.validation_notification({**PROPERTIES, "url": bad})

    def test_validation_status_sibling_empty_issuance_and_duplicates(self):
        raw = VALIDATION.replace(b"<response>", b"<response>" + STATUS)
        self.assertEqual(ep.validation_response(raw)["dosPreventer"], "synthetic-dos")
        empty = raw.replace(b"synthetic-dos", b"").replace(b"synthetic-group", b"").replace(b"synthetic-name", b"")
        parsed = ep.parse_validation_response(empty)
        self.assertEqual(parsed.status_disposition, "success"); self.assertEqual(parsed.status_error_id, 0)
        self.assertFalse(any(parsed.fields.values()))
        with self.assertRaisesRegex(Exception, "validation_credentials_missing"): ep.validation_response(empty)
        for invalid in (raw.replace(STATUS, STATUS + STATUS), raw.replace(b"<error-id>0</error-id>", b"<error-id>0</error-id><error-id>0</error-id>"),
                        raw.replace(b'<status disposition=', b'<status xmlns="evil" disposition='),
                        raw.replace(b"</response>", b"<phoneAppValidateDeviceTokenResponse/></response>")):
            with self.assertRaises(Exception): ep.parse_validation_response(invalid)
        with self.assertRaisesRegex(Exception, "validation_status_rejected"):
            ep.validation_response(raw.replace(b'<error-id>0', b'<error-id>1'))

    def test_fresh_input_account_and_age(self):
        value = {"activation_code": CODE, "service_base_url": BASE, "expected_account": ACCOUNT,
                 "created_at": 100, "fresh_code": True}
        self.assertEqual(x.validate_input(value, now=101)[1], ACCOUNT)
        for change in ({"created_at": -999}, {"created_at": 102}, {"fresh_code": False},
                       {"expected_account": ""}, {"service_base_url": "https://evil.invalid"}):
            with self.assertRaises(Exception): x.validate_input({**value, **change}, now=101)

    def test_http_framing_redirect_is_not_followed_and_injection(self):
        self.assertEqual(x.parse_http(http(b"synthetic")), (200, b"synthetic"))
        self.assertEqual(x.parse_http(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n"), (200, b"x"))
        for raw in (http(b"x") + b"extra", http(b"x").replace(b"Content-Length: 1", b"Content-Length: 1\r\nContent-Length: 1"),
                    http(b"x").replace(b"Content-Length: 1", b"Content-Length: 1\r\nTransfer-Encoding: chunked"),
                    http(b"x").replace(b"Content-Length: 1", b"Content-Length: 9"),
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nextra"):
            with self.assertRaises(Exception): x.parse_http(raw)
        for request in (p.Request(BASE + "/other", {}, b"x"), p.Request(BASE + "/pad", {"Host": "evil"}, b"x"),
                        p.Request(BASE + "/pad", {"X-Test": "a\r\nb"}, b"x")):
            with self.assertRaises(Exception): x.request_wire("validate", request, ENROLLMENT)


class Executor(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.no_dns = patch.object(socket, "getaddrinfo", side_effect=AssertionError("Real DNS forbidden")).start()
        self.addCleanup(patch.stopall)

    async def asyncTearDown(self): self.no_dns.assert_not_called()

    async def simulate(self, *, activation=ACTIVATION, validation=VALIDATION, confirmation=CONFIRMATION,
                       notification=None, reject_login=False, activate_waits_for_validate=False, block_push=False,
                       activate_delay=False, ignored_guids=frozenset()):
        report, run, calls, closed = x.new_report(), Run(), [], []
        validated = asyncio.Event()
        class Writer:
            def __init__(self): self.sent = []
            def write(self, value): self.sent.append(value)
            async def drain(self): pass
        class Reader:
            def __init__(self, kind, payload): self.kind, self.payload, self.first = kind, payload, True
            async def read(self, size):
                if self.kind == "activate" and self.first and activate_delay:
                    self.first = False
                    await asyncio.sleep(0.02)
                if self.kind == "activate" and activate_waits_for_validate:
                    await validated.wait()
                if self.kind == "mcs" and not self.payload and block_push:
                    await asyncio.Event().wait()
                result, self.payload = self.payload[:min(size, 7)], self.payload[min(size, 7):]
                return result
        login = p.field(1, "synthetic-login")
        if reject_login: login += p.field(3, p.field(1, 7))
        mcs_data = p.mcs_frame(3, login, first=True)
        if not block_push: mcs_data += data() if notification is None else notification
        payloads = {"mcs": mcs_data, "activate": http(activation), "validate": http(validation), "confirm": http(confirmation)}
        @asynccontextmanager
        async def connect(host, port, kind, report):
            self.assertEqual(report[kind + "_connections_attempted"], 0)
            report[kind + "_connections_attempted"] += 1; report[kind + "_tls_verified"] = True
            calls.append(kind)
            if kind == "validate": validated.set()
            try: yield Reader(kind, payloads[kind]), Writer()
            finally: closed.append(kind)
        config = type("Config", (), {"sender_id": x.p03.SENDER, "package": x.p03.PACKAGE})()
        error = None
        with patch.object(x, "connection", connect):
            try: await x.exchange((config, CREDS, TOKEN, ENROLLMENT, ACCOUNT), run, report, ignored_guids=ignored_guids)
            except Exception as exc: error = x.safe_error(exc)
        return report, run, calls, closed, error

    async def test_concurrent_success_three_posts_and_no_approval(self):
        report, run, calls, closed, error = await self.simulate(activate_waits_for_validate=True)
        self.assertIsNone(error)
        self.assertEqual(calls, ["mcs", "activate", "validate", "confirm"])
        self.assertCountEqual(calls, closed)
        self.assertTrue(report["enrollment_completed"])
        self.assertEqual(report["http_posts_attempted"], 3)
        self.assertEqual(report["authentication_approvals_sent"], 0)
        self.assertFalse(report["same_mac_sign_in_approved"])
        for secret in (ACCOUNT, TOKEN, CODE, "synthetic-dos", "synthetic-oath-key", "synthetic-confirmation"):
            self.assertNotIn(secret, json.dumps(report))
        self.assertIn(b"synthetic-dos", run.files["validation.json"])

    async def test_rejected_bootstrap_cancels_waiting_listener_without_retry(self):
        raw = soap("ActivateNew", {"ActivateNewResult": "false", "Code": "15"})
        report, _, calls, closed, error = await self.simulate(activation=raw, block_push=True)
        self.assertEqual(error, "activation_rejected")
        self.assertEqual(calls, ["mcs", "activate"]); self.assertCountEqual(calls, closed)
        self.assertEqual(report["service_error_code"], 15)

    async def test_login_rejection_sends_no_microsoft_request(self):
        report, _, calls, _, error = await self.simulate(reject_login=True)
        self.assertEqual(error, "mcs_login_rejected"); self.assertEqual(calls, ["mcs"])
        self.assertEqual(report["http_posts_attempted"], 0)

    async def test_prior_p02_control_replay_is_not_microsoft_validation(self):
        replay = data({"p02_kind": "native-mac-control", "p02_nonce": "synthetic-old-nonce"},
                      sender="123", package=x.prep.PACKAGE)
        configuration = (Path(__file__).resolve().parents[1] / "fixtures/p02-synthetic-config.json").read_bytes()
        with patch.object(x.prep, "private_config", return_value=configuration):
            report, _, calls, _, error = await self.simulate(notification=replay + data())
        self.assertIsNone(error); self.assertTrue(report["enrollment_completed"])
        self.assertEqual(report["prior_own_project_control_messages_ignored"], 1)
        self.assertEqual(calls.count("validate"), 1)

    async def test_old_validation_guid_ignored_before_any_callback(self):
        replay = data({**PROPERTIES, "guid": "synthetic-old-guid"})
        report, run, calls, _, error = await self.simulate(notification=replay + data(),
                                                         ignored_guids=frozenset(("synthetic-old-guid",)))
        self.assertIsNone(error)
        self.assertEqual(report["prior_validation_notifications_ignored"], 1)
        self.assertEqual(calls.count("validate"), 1)
        self.assertNotIn(b"synthetic-old-guid", run.files["notification.json"])

    async def test_auth_and_wrong_sender_never_validated_or_approved(self):
        for notification in (data({**PROPERTIES, "type": "auth"}), data(sender="999999"), data(package="other.app"),
                             data({**PROPERTIES, "url": "evil.invalid"}), data({**PROPERTIES, "deviceTokenChangeVersion": "V2"})):
            report, _, calls, closed, error = await self.simulate(notification=notification)
            self.assertIsNotNone(error); self.assertNotIn("validate", calls); self.assertNotIn("confirm", calls)
            self.assertCountEqual(calls, closed); self.assertEqual(report["authentication_approvals_sent"], 0)

    async def test_wrong_account_missing_dos_or_false_confirmation_never_completes(self):
        for change in ({"activation": ACTIVATION.replace(ACCOUNT.encode(), b"other@example.invalid")},
                       {"validation": VALIDATION.replace(b"synthetic-dos", b"")},
                       {"confirmation": CONFIRMATION.replace(b">true<", b">false<")}):
            report, _, calls, closed, error = await self.simulate(**change)
            self.assertIsNotNone(error); self.assertFalse(report["enrollment_completed"])
            self.assertCountEqual(calls, closed)
            if "confirmation" not in change: self.assertNotIn("confirm", calls)

    async def test_timeout_cancels_every_task_and_connection(self):
        with patch.object(x, "PUSH_SECONDS", 0.02):
            report, _, calls, closed, error = await self.simulate(block_push=True)
        self.assertEqual(error, "network_timeout")
        self.assertCountEqual(calls, closed); self.assertNotIn("confirm", calls)
        self.assertFalse(report["enrollment_completed"])

    async def test_push_parser_failure_preserves_inflight_activation_response(self):
        report, run, calls, closed, error = await self.simulate(
            notification=data({**PROPERTIES, "url": "evil.invalid"}), activate_delay=True)
        self.assertIsNotNone(error)
        self.assertIn("activation.json", run.files)
        self.assertTrue(report["bootstrap_accepted"])
        self.assertNotIn("validate", calls); self.assertNotIn("confirm", calls)
        self.assertCountEqual(calls, closed)

    async def test_request_budget_blocks_transport(self):
        report = x.new_report(); report["http_posts_attempted"] = 3
        with patch.object(x, "connection") as connect:
            with self.assertRaises(Exception): await x.post("activate", ep.activate(ENROLLMENT, TOKEN), ENROLLMENT, Run(), report)
            connect.assert_not_called()

    async def test_connection_rejects_private_dns_before_socket(self):
        private = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443))]
        with patch.object(x, "resolve", return_value=private), patch.object(socket, "socket") as sock:
            with self.assertRaisesRegex(Exception, "invalid_or_nonpublic_dns"):
                async with x.connection("synthetic.example.invalid", 443, "activate", x.new_report()): pass
            sock.assert_not_called()


class Storage(unittest.TestCase):
    def root(self):
        parent = Path(__file__).resolve().parents[2] / "work"
        tmp = tempfile.TemporaryDirectory(prefix="e02-offline-", dir=parent)
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for path in (".secrets", ".secrets/push", ".secrets/push/e02-setup"):
            (root / path).mkdir(mode=0o700)
        return root

    def test_attempt_lock_private_files_redaction_and_no_rerun(self):
        root = self.root()
        async def failed(inputs, run, report):
            run.write("activation.json", b'{"private":"synthetic-private-result"}')
            raise ssl.SSLCertVerificationError("synthetic-private-error")
        with patch.object(x, "prerequisites", return_value=None), patch.object(x, "exchange", failed), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("No DNS")):
            report = x.run_once(root)
            self.assertEqual(report["error"], "tls_certificate_verification_failed")
            self.assertNotIn("synthetic-private", json.dumps(report))
            with self.assertRaisesRegex(Exception, "attempt_already_reserved"):
                x.run_once(root)
        lock = x.rt.private_json(root / ".secrets/push/e02-attempt.lock")
        folder = root / ".secrets/push" / lock["run_id"]
        self.assertEqual(stat.S_IMODE(folder.stat().st_mode), 0o700)
        for file in folder.iterdir(): self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)

    def test_protected_input_setup_no_echo_no_network_and_no_overwrite(self):
        root = self.root()
        with patch.object(x, "load_identity"), \
             patch.object(e01, "secret_prompt", side_effect=[ACCOUNT, CODE, BASE, "FRESH"]), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("No DNS")):
            report = x.setup(root, True)
        self.assertNotIn(CODE, json.dumps(report)); self.assertEqual(report["network_requests"], 0)
        path = root / ".secrets/push/e02-setup/input.json"
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(x.rt.private_json(path)["activation_code"], CODE)
        with patch.object(x, "load_identity"), patch.object(e01, "secret_prompt") as prompt:
            with self.assertRaisesRegex(Exception, "protected_input_already_exists"): x.setup(root, True)
            prompt.assert_not_called()

    def test_missing_or_bad_provenance_input_never_reserves_attempt(self):
        root = self.root()
        with patch.object(socket, "getaddrinfo", side_effect=AssertionError("No DNS")):
            with self.assertRaises(Exception): x.run_once(root)
        self.assertFalse((root / ".secrets/push/e02-attempt.lock").exists())


if __name__ == "__main__": unittest.main()
