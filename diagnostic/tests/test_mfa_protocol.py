"""Synthetic classic-MFA codec/transport tests. Never read research credentials."""
import asyncio
from contextlib import asynccontextmanager
import hashlib
import json
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import e03
import mfa_protocol as x
import mfa_transport as t
import push_protocol as p
import test_e02 as f

A = x.Account("synthetic-token<&", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", f.ACCOUNT,
              "synthetic-tenant", "synthetic-object", "synthetic-group", "synthetic-method", "synthetic-dos")
SERVICE = f.BASE[8:] + "/mac/Synthetic.svc/?dc=synthetic"


def response(fields=None):
    root = ET.Element("pfpMessage", {"version": "1.6"})
    wrapper = ET.SubElement(root, "response")
    wrapper.append(ET.fromstring(f.STATUS))
    body = ET.SubElement(wrapper, "phoneAppCheckForAuthenticationResponse")
    for key, value in (fields or {"checkForAuthenticationResult": "1"}).items():
        ET.SubElement(body, key).text = value
    return ET.tostring(root)


PENDING = {"checkForAuthenticationResult": "1", "username": A.username, "groupKey": A.group_key,
           "phoneAppDetailId": A.method_id, "padUrl": SERVICE, "oathCounter": "1"}


class Codecs(unittest.TestCase):
    def test_full_hmac_sha1_vector(self):
        self.assertEqual(x.oath_proof(A.secret, 1), "75A48A19D4CBE100644E8AC1397EEA747A2D33AB")
        for counter in (0, -1, True, "1", 2**63):
            with self.assertRaises(Exception): x.oath_proof(A.secret, counter)
        with self.assertRaises(Exception): x.oath_proof("not a base32 secret", 1)

    def test_poll_serialization_and_token_hash(self):
        req = x.poll(A)
        body = ET.fromstring(req.body).find("request/phoneAppCheckForAuthenticationRequest")
        self.assertEqual([n.tag for n in body], ["dosPreventer", "deviceToken", "previousDeviceToken", "version", "osVersion", "AuthenticatorFlavor"])
        self.assertEqual(body.findtext("deviceToken"), A.token)
        self.assertEqual(body.find("deviceToken").attrib, {"notificationType": "gcm"})
        self.assertEqual(req.headers["x-ms-mac-device-token"], hashlib.sha256(A.token.encode()).hexdigest())
        self.assertNotIn(A.token, repr(req)); self.assertNotIn(A.secret, repr(A))
        self.assertEqual(req.url, x.POLL_URL)

    def test_poll_empty_and_rejections(self):
        result, _ = x.poll_response(response(), A)
        self.assertEqual(result, {"result": 1, "pending": False})
        for code in ("100", "101"):
            self.assertEqual(x.poll_response(response({"checkForAuthenticationResult": code}), A)[0],
                             {"result": int(code), "pending": False})
        with self.assertRaises(Exception): x.poll_response(response({"checkForAuthenticationResult": "999"}), A)

    def test_pending_account_binding_and_url(self):
        self.assertTrue(x.poll_response(response(PENDING), A)[0]["pending"])
        for key, bad in (("username", "other@example.invalid"), ("groupKey", "other"),
                         ("phoneAppDetailId", "other"), ("padUrl", "evil.invalid"),
                         ("oathCounter", "0"), ("oathCounter", "9223372036854775808")):
            with self.subTest(key=key), self.assertRaises(Exception):
                x.poll_response(response({**PENDING, key: bad}), A)
        with self.assertRaises(Exception): x.poll_response(response({**PENDING, "padUrl": ""}), A)

    def test_envelope_duplicates_status_and_namespace(self):
        raw = response()
        for invalid in (raw.replace(b"</response>", b"<phoneAppCheckForAuthenticationResponse/></response>"),
                        raw.replace(b"</response>", f.STATUS + b"</response>"),
                        raw.replace(b"<checkForAuthenticationResult>", b"<checkForAuthenticationResult xmlns='evil'>"),
                        raw.replace(b"<error-id>0", b"<error-id>1"),
                        raw.replace(b"</checkForAuthenticationResult>", b"</checkForAuthenticationResult><checkForAuthenticationResult>1</checkForAuthenticationResult>"),
                        b'<!DOCTYPE x [<!ENTITY e "bad">]>' + raw):
            with self.assertRaises(Exception): x.poll_response(invalid, A)

    def test_retrieval_proof_and_literal_route(self):
        req = x.retrieve(A, SERVICE, "synthetic-guid", 1)
        ctx = ET.fromstring(req.body).find("request/phoneAppAuthenticationRequest/phoneAppContext")
        self.assertEqual(ctx.findtext("oathCode"), x.oath_proof(A.secret, 1))
        self.assertEqual(ctx.findtext("guid"), "synthetic-guid")
        self.assertEqual(ctx.findtext("needDosPreventer"), "no")
        self.assertEqual(req.url, "https://" + SERVICE + "/pad")
        self.assertTrue(t.wire("retrieve", req)[1].startswith(b"POST /mac/Synthetic.svc/?dc=synthetic/pad HTTP/1.1"))

    def test_wire_rejects_destinations_and_header_injection(self):
        req = x.poll(A)
        for bad in (p.Request("https://evil.invalid/", req.headers, req.body),
                    p.Request(req.url, {**req.headers, "Host": "evil"}, req.body),
                    p.Request(req.url, {**req.headers, "X-Test": "a\r\nb"}, req.body)):
            with self.assertRaises(Exception): t.wire("poll", bad)
        with self.assertRaises(Exception): t.wire("number", req)


class Executor(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.dns = patch.object(socket, "getaddrinfo", side_effect=AssertionError("Real DNS forbidden")).start()
        self.addCleanup(patch.stopall)

    async def asyncTearDown(self): self.dns.assert_not_called()

    async def test_one_poll_private_response_redacted_report_and_budget(self):
        reader = asyncio.StreamReader(); reader.feed_data(f.http(response())); reader.feed_eof()
        writes = []
        class Writer:
            def write(self, b): writes.append(b)
            async def drain(self): pass
        @asynccontextmanager
        async def connection(*args): yield reader, Writer()
        state, run = t.report("E03", ("poll",), 1), f.Run()
        with patch.object(t.e02, "connection", connection):
            await e03.perform(A, run, state)
            with self.assertRaisesRegex(Exception, "budget_exhausted"):
                await t.post("poll", x.poll(A), run, state)
        self.assertEqual(len(writes), 1)
        self.assertTrue(state["polling_credentials_accepted"])
        self.assertEqual(state["authentication_approvals_sent"], 0)
        self.assertIn("poll-body.bin", run.files)
        for value in (A.token, A.secret, A.dos_preventer, A.username):
            self.assertNotIn(value, json.dumps(state))

    async def test_failure_not_retried(self):
        calls = []
        async def post(*args): calls.append(args[0]); raise TimeoutError("synthetic-secret")
        with patch.object(t, "post", post), self.assertRaises(TimeoutError):
            await e03.perform(A, f.Run(), t.report("E03", ("poll",), 1))
        self.assertEqual(calls, ["poll"])

    async def test_http_rejection_saved_no_followup(self):
        reader = asyncio.StreamReader(); reader.feed_data(f.http(b"synthetic-private-error", 302)); reader.feed_eof()
        class Writer:
            def write(self, b): pass
            async def drain(self): pass
        @asynccontextmanager
        async def connection(*args): yield reader, Writer()
        state, run = t.report("E03", ("poll",), 1), f.Run()
        with patch.object(t.e02, "connection", connection), self.assertRaisesRegex(Exception, "poll_http_rejected"):
            await e03.perform(A, run, state)
        self.assertEqual(state["http_posts_attempted"], 1)
        self.assertEqual(run.files["poll-body.bin"], b"synthetic-private-error")
