"""Synthetic bounded push/retrieval tests; no network or private input."""
import asyncio
from contextlib import asynccontextmanager
import json
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import auth_request as auth
import e04 as x
import test_e02 as f
import test_mfa_protocol as m

NOTICE = {"source": "SAS", "type": "auth", "guid": "synthetic-guid", "groupKey": m.A.group_key,
          "phoneAppDetailId": m.A.method_id, "url": m.SERVICE, "oathCounter": "1"}
DETAILS = {"guid": "synthetic-response-guid", "username": m.A.username, "groupKey": m.A.group_key,
           "phoneAppDetailId": m.A.method_id, "tenantId": m.A.tenant_id, "azureObjectId": m.A.object_id,
           "expiration": "1700000060", "firstEntropyChallenge": "42", "isAppLockRequired": "no"}


def response(fields=None):
    root = ET.Element("pfpMessage", {"version": "1.6"})
    wrapper = ET.SubElement(root, "response"); wrapper.append(ET.fromstring(f.STATUS))
    op = ET.SubElement(wrapper, "phoneAppAuthenticationResponse")
    body = ET.SubElement(op, "phoneAppInfo", {"mode": "pin"})
    for name, value in (DETAILS if fields is None else fields).items(): ET.SubElement(body, name).text = value
    return ET.tostring(root)


class Codecs(unittest.TestCase):
    def test_bound_notification(self):
        self.assertEqual(auth.notification(NOTICE, m.A), (m.SERVICE, "synthetic-guid", 1))
        for key, bad in (("source", "other"), ("type", "validate"), ("groupKey", "other"),
                         ("phoneAppDetailId", "other"), ("url", "evil.invalid"), ("oathCounter", "0"),
                         ("oathCounter", ""), ("guid", "")):
            with self.subTest(key=key), self.assertRaises(Exception):
                auth.notification({**NOTICE, key: bad}, m.A)

    def test_response_identity_binding(self):
        fields = auth.response(response(), m.A)
        self.assertEqual(fields["mode"], "pin")
        for key in ("username", "groupKey", "phoneAppDetailId", "tenantId", "azureObjectId", "pushNotificationDeviceToken"):
            with self.subTest(key=key), self.assertRaises(Exception):
                auth.response(response({**DETAILS, key: "other"}), m.A)

    def test_response_duplicate_unknown_and_expiry_rejection(self):
        raw = response()
        for invalid in (raw.replace(b"</phoneAppInfo>", b"<guid>duplicate</guid></phoneAppInfo>"),
                        raw.replace(b"</phoneAppAuthenticationResponse>", b"<phoneAppInfo/></phoneAppAuthenticationResponse>"),
                        raw.replace(b"<guid>", b"<guid xmlns='evil'>"),
                        response({**DETAILS, "unexpected": "value"}),
                        response({**DETAILS, "expiration": "0"}), response({**DETAILS, "guid": ""})):
            with self.assertRaises(Exception): auth.response(invalid, m.A)

    def test_summary_contains_no_sensitive_values(self):
        safe = json.dumps(auth.summary(auth.response(response(), m.A)))
        for value in ("synthetic", m.A.username, m.A.group_key, m.A.method_id, "42"):
            self.assertNotIn(value, safe)


class Executor(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.dns = patch.object(socket, "getaddrinfo", side_effect=AssertionError("Real DNS forbidden")).start()
        self.addCleanup(patch.stopall)

    async def asyncTearDown(self): self.dns.assert_not_called()

    async def simulate(self, notice=NOTICE, fail_post=False):
        state, run, calls, ready_calls = x.new_report(), f.Run(), [], []
        config = SimpleNamespace(sender_id=x.e02.p03.SENDER, package=x.e02.p03.PACKAGE)
        frames = []
        # Use the actual frame decoder; f.data supplies a complete encoded frame.
        for props in ({**f.PROPERTIES, "guid": "old"}, notice):
            decoder = x.e02.p.MCSDecoder()
            frames.extend(decoder.feed(bytes([41]) + f.data(props)))
        class MCS:
            def __init__(self, reader, writer, capture, report): self.report = report
            async def login(self, credentials):
                self.report["mcs_logins_attempted"] += 1; self.report["mcs_accepted"] = True
            async def frame(self): return frames.pop(0)
        @asynccontextmanager
        async def connection(host, port, kind, report):
            calls.append(kind); report[kind + "_connections_attempted"] += 1
            yield None, None
        async def post(kind, req, private, report):
            calls.append(kind); report["http_posts_attempted"] += 1
            if fail_post: raise TimeoutError("synthetic-private-failure")
            self.assertEqual(ET.fromstring(req.body).findtext("request/phoneAppAuthenticationRequest/phoneAppContext/oathCode"), m.x.oath_proof(m.A.secret, 1))
            return response()
        with patch.object(x.e02, "connection", connection), patch.object(x.e02, "MCS", MCS), patch.object(x.transport, "post", post):
            try:
                await x.perform((m.A, config, f.CREDS, frozenset({"old"})), run, state, lambda: ready_calls.append(True))
            except Exception as exc: state["error"] = x.e02.safe_error(exc)
        return state, run, calls, ready_calls

    async def test_one_connection_one_retrieval_never_approval(self):
        state, run, calls, ready = await self.simulate()
        self.assertEqual(calls, ["mcs", "retrieve"]); self.assertEqual(ready, [True])
        self.assertTrue(state["request_details_retrieved"])
        self.assertEqual(state["prior_validation_messages_ignored"], 1)
        self.assertEqual(state["authentication_approvals_sent"], 0)
        self.assertEqual(state["authentication_denials_sent"], 0)
        self.assertIn("notification.json", run.files); self.assertIn("request-details.json", run.files)

    async def test_wrong_method_never_retrieved(self):
        state, run, calls, _ = await self.simulate({**NOTICE, "phoneAppDetailId": "other"})
        self.assertEqual(calls, ["mcs"]); self.assertEqual(state["error"], "notification_account_mismatch")
        self.assertIn("notification.json", run.files)

    async def test_no_retry_after_retrieval_failure(self):
        state, run, calls, _ = await self.simulate(fail_post=True)
        self.assertEqual(calls, ["mcs", "retrieve"])
        self.assertFalse(state["request_details_retrieved"])
        self.assertNotIn("synthetic-private-failure", json.dumps(state))

    async def test_unexpected_notification_saved_but_not_retrieved(self):
        state, run, calls, _ = await self.simulate({**NOTICE, "type": "validate"})
        self.assertEqual(calls, ["mcs"])
        self.assertEqual(state["error"], "unexpected_microsoft_notification")
