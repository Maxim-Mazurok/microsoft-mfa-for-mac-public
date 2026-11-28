"""Synthetic controller separation. No private input, network or enrollment."""
import asyncio
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from controller import Controller, ServiceError
import credentials
import remotengc
from state import StateStore
from test_service import BUNDLE, SERVICE, browser, details


def ngc_push(account):
    return {"source": "SAS", "type": "NGC", "sessiontype": "ngc",
        "sessionid": "synthetic-opaque-session-not-a-uuid", "tenantid": account.tenant_id,
        "userobjectidhash": remotengc.object_id_hash(account.object_id),
        "requesttime": str(int(time.time())), "expirationtime": str(int(time.time()) + 60),
        "firstentropychallenge": "10", "secondentropychallenge": "20", "thirdentropychallenge": "30",
        "authdetails": json.dumps({"ApplicationDisplayName": "Synthetic app"})}


def ngc_browser(props, account, *, bound=True):
    return {"version": 1, "kind": "challenge", "event_id": uuid.uuid4().hex,
        "tab_id": "ngc-test-tab", "document_id": uuid.uuid4().hex,
        "origin": "https://login.microsoftonline.com", "observed_at": time.time(),
        "number": "42", "account": account.username, "application": "Synthetic app",
        "session_id": "", "request_id": "", "focused": True, "flow": "remote_ngc",
        "remote_session_hash": remotengc.remote_session_hash(props["sessionid"]) if bound else ""}


class NgcDispatch(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = StateStore(Path(self.directory.name).resolve(), synthetic=True)
        self.events = []
        self.sent = []
        async def forbidden(*args):
            self.sent.append(True)
            raise AssertionError("network forbidden")
        self.controller = Controller(self.store, self.events.append, synthetic=True, sender=forbidden)
        await self.command("configure", credentials=None, settings={"automatic": True})
        await self.command("session_lock", locked=False)
        bundle = copy.deepcopy(BUNDLE)
        bundle["account"].update(tenant_id="11111111-2222-3333-4444-555555555555",
                                  object_id="66666666-7777-8888-9999-aaaaaaaaaaaa")
        self.controller.credentials = credentials.validate(bundle)
        self.account = self.controller.credentials.account
        self.props = ngc_push(self.account)

    async def asyncTearDown(self):
        await self.command("shutdown")
        self.store.close()
        self.directory.cleanup()

    async def command(self, name, **fields):
        return await self.controller.command({"version": 1, "command": name, **fields})

    async def receive(self, props):
        with patch("controller.p.parse_android_data", return_value=SimpleNamespace(properties=props)):
            await self.controller.receive(object())

    def capability(self):
        return [e for e in self.events if e["event"] == "capability"]

    async def test_detection_only_reports_capability_without_approval(self):
        event = ngc_browser(self.props, self.account, bound=False)
        await self.command("browser_event", browser=event)
        await self.command("browser_event", browser=event)
        self.assertEqual(self.capability(), [{"version": 1, "event": "capability",
            "flow": "remote_ngc", "status": "session_binding_unavailable"}])
        self.assertFalse(self.controller.pending)
        self.assertFalse(self.sent)

    async def test_exact_remote_pair_still_requires_its_registered_key(self):
        await self.command("browser_event", browser=ngc_browser(self.props, self.account))
        await self.receive(self.props)
        await self.receive(self.props)
        self.assertEqual(len(self.controller.ngc_candidates), 1)
        request_id, _ = next(iter(self.controller.ngc_candidates.values()))
        self.assertIsNotNone(self.controller.engine.match(request_id, time.time()))
        self.assertEqual(self.capability()[-1]["status"], "registration_required")
        self.assertFalse(self.controller.pending)
        self.assertFalse(self.sent)
        serialized = json.dumps(self.events)
        for secret in (self.props["sessionid"], self.props["userobjectidhash"], self.account.username,
                       remotengc.remote_session_hash(self.props["sessionid"])):
            self.assertNotIn(secret, serialized)

    async def test_ngc_dispatch_cannot_fall_back_to_classic_auth(self):
        props = {**self.props, "type": "auth", "phoneAppDetailId": self.account.method_id}
        with patch("controller.approval.push_details", side_effect=AssertionError("classic forbidden")):
            await self.receive(props)
        self.assertEqual(self.capability()[-1]["status"], "registration_required")
        self.assertFalse(self.controller.pending)

    async def test_other_account_or_tenant_not_offered(self):
        for change in ({"userobjectidhash": "other-account"},
                       {"tenantid": "00000001-0002-0003-0004-000000000005"}):
            await self.receive({**self.props, **change})
        self.assertFalse(self.capability())
        self.assertFalse(self.controller.ngc_candidates)

    async def test_missing_or_expired_context_cannot_be_used(self):
        for change in ({"expirationtime": "1"}, {"sessionid": ""}, {"source": "untrusted"}):
            await self.receive({**self.props, **change})
        self.assertFalse(self.controller.ngc_candidates)
        self.assertFalse(self.sent)
        self.assertEqual([e["code"] for e in self.events if e["event"] == "error"],
                         ["unsupported_or_invalid_push"] * 3)

    async def test_classic_still_automatically_completes_with_remote_page_present(self):
        await self.command("browser_event", browser=ngc_browser(self.props, self.account))
        d = details()
        await self.command("browser_event", browser=browser(d))
        await self.controller.add_request(d, SERVICE)
        await asyncio.sleep(0)
        if self.controller.approval_tasks:
            await asyncio.gather(*self.controller.approval_tasks)
        self.assertEqual([e["result"] for e in self.events if e["event"] == "outcome"], ["synthetic_accepted"])
        self.assertFalse(self.sent)

    async def test_remote_fields_refused_by_classic_entry_point(self):
        for change in ({"flow": "remote_ngc"}, {"sessiontype": "NGC"}):
            with self.assertRaisesRegex(ServiceError, "classic_flow_required"):
                await self.controller.add_request({**details(), **change}, SERVICE)
        self.assertFalse(self.controller.pending)

    async def test_remote_candidate_expires_and_has_no_manual_approval(self):
        await self.receive(self.props)
        fingerprint, (request_id, _) = next(iter(self.controller.ngc_candidates.items()))
        with self.assertRaisesRegex(ServiceError, "unknown_request"):
            await self.command("manual_approve", request_id=request_id, number="42")
        self.controller.ngc_candidates[fingerprint] = (request_id, time.time() - 1)
        await self.controller.tick()
        self.assertFalse(self.controller.ngc_candidates)
        self.assertNotIn(request_id, self.controller.engine.requests)


if __name__ == "__main__": unittest.main()
