"""Synthetic lifecycle tests. No research credentials are loaded and no network is used."""
import asyncio
import base64
from contextlib import asynccontextmanager
import copy
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid
import xml.etree.ElementTree as ET

SERVICE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE_DIR))
import bootstrap
import approval_protocol as approval
from controller import Controller, ServiceError
import credentials
import push_protocol as p
from state import StateStore, StateError
import transport


BUNDLE = {"version": 1, "provider": {"android_id": "12345", "security_token": "67890", "token": "synthetic-device-token",
          "sender_id": "275572744697", "package": "com.azure.authenticator"}, "account": {
          "secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "username": "demo@example.test", "tenant_id": "synthetic-tenant",
          "object_id": "synthetic-object", "group_key": "synthetic-group", "method_id": "synthetic-method", "dos_preventer": "synthetic-dos"}}
SERVICE = "synthetic.mobileappcommunicator.auth.microsoft.com/mac/Synthetic.svc/?dc=synthetic"


def details(verify=False, context=False):
    value = {"guid": str(uuid.uuid4()), "username": "demo@example.test", "sasSessionId": str(uuid.uuid4()),
        "expiration": str(int(time.time()) + 90), "firstEntropyChallenge": "10", "secondEntropyChallenge": "20", "thirdEntropyChallenge": "30",
        "isAppLockRequired": "yes" if verify else "no", "authDetails": json.dumps({"ApplicationDisplayName": "Synthetic app", "Latitude": 0, "Longitude": 0})}
    if context:
        value["userCredentialPolicy"] = base64.b64encode(p.field(2, p.field(3, 2) + p.field(4, 2) + p.field(8, 1))).decode()
    return value


def browser(fields, tab="one"):
    return {"version": 1, "kind": "challenge", "event_id": uuid.uuid4().hex, "tab_id": tab, "document_id": uuid.uuid4().hex,
        "origin": "https://login.microsoftonline.com", "observed_at": time.time(), "number": "42", "account": fields["username"],
        "application": "Synthetic app", "session_id": fields["sasSessionId"], "request_id": "", "focused": True}


def response(code=6):
    return (f'<pfpMessage version="1.6"><response><status disposition="success"><error-id>0</error-id><message lang="en"/></status>'
            f'<phoneAppPinValidationResponse><validationResult>{code}</validationResult></phoneAppPinValidationResponse></response></pfpMessage>').encode()


class Lifecycle(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = StateStore(Path(self.temp.name).resolve(), synthetic=True)
        self.events = []
        self.service = Controller(self.store, self.events.append, synthetic=True)
        await self.command("configure", credentials=None, settings={"automatic": True})
        await self.command("session_lock", locked=False)

    async def asyncTearDown(self):
        await self.command("shutdown")
        self.store.close(); self.temp.cleanup()

    async def command(self, command, **fields):
        return await self.service.command({"version": 1, "command": command, **fields})

    async def settle(self):
        await asyncio.sleep(0)
        if self.service.approval_tasks: await asyncio.gather(*self.service.approval_tasks)

    async def add(self, fields, *, event=None):
        if event:
            await self.command("browser_event", browser=event)
        return await self.service.add_request(fields, SERVICE)

    def outcomes(self): return [e["result"] for e in self.events if e["event"] == "outcome"]

    async def test_unique_exact_session_automatically_submits_once(self):
        d = details(); event = browser(d)
        item = await self.add(d, event=event); await self.settle()
        self.assertEqual(self.outcomes(), ["synthetic_accepted"])
        await self.add(d); await self.command("browser_event", browser=event); await self.settle()
        self.assertEqual(self.outcomes(), ["synthetic_accepted"])
        self.assertTrue(self.store.consumed(item.digest))

    async def test_two_tabs_ambiguous_never_submit(self):
        d = details()
        await self.command("browser_event", browser=browser(d, "one"))
        await self.command("browser_event", browser=browser(d, "two"))
        await self.add(d); await self.settle()
        self.assertFalse(self.outcomes())

    async def test_push_before_browser_does_not_demand_context_or_verification(self):
        d = details(verify=True, context=True)
        item = await self.add(d)
        self.assertEqual([e["status"] for e in self.events if e["event"] == "pending"], ["waiting_for_browser"])
        self.assertFalse([e for e in self.events if e["event"] == "verification_required"])
        await self.command("browser_event", browser=browser(d))
        self.assertEqual([e["status"] for e in self.events if e["event"] == "pending"], ["waiting_for_browser", "show_context"])
        await self.command("context_shown", request_id=item.local_id, app_context_shown=True, location_context_shown=False)
        self.assertFalse(item.ticket)
        await self.command("context_shown", request_id=item.local_id, app_context_shown=True, location_context_shown=True)
        self.assertTrue(item.ticket)
        ticket = item.ticket
        await self.command("verification_result", request_id=item.local_id, ticket_id=ticket, verified=True)
        await self.settle()
        self.assertEqual(self.outcomes(), ["synthetic_accepted"])
        with self.assertRaises(ServiceError):
            await self.command("verification_result", request_id=item.local_id, ticket_id=ticket, verified=True)

    async def test_context_event_emission_is_not_claimed_as_actual_display(self):
        d = details(context=True); item = await self.add(d, event=browser(d))
        await self.settle()
        self.assertFalse(item.app_context_shown); self.assertFalse(item.location_context_shown)
        self.assertFalse(self.outcomes())

    async def test_verification_cancellation_is_durable_and_no_auto_reprompt(self):
        d = details(verify=True); item = await self.add(d, event=browser(d))
        await self.command("verification_result", request_id=item.local_id, ticket_id=item.ticket, verified=False)
        await self.add(d, event=browser(d)); await self.settle()
        self.assertEqual(self.outcomes(), ["verification_cancelled"])
        self.assertTrue(self.store.consumed(item.digest)); self.assertFalse(self.service.pending)
        self.assertEqual(sum(e["event"] == "verification_required" for e in self.events), 1)

    async def test_withdraw_during_verification_prevents_approval(self):
        d = details(verify=True); event = browser(d); item = await self.add(d, event=event)
        ticket = item.ticket
        await self.command("browser_event", browser={**event, "kind": "withdraw"})
        with self.assertRaises(ServiceError):
            await self.command("verification_result", request_id=item.local_id, ticket_id=ticket, verified=True)
        await self.settle(); self.assertFalse(self.outcomes()); self.assertFalse(self.store.consumed(item.digest))

    async def test_lock_invalidates_ticket_and_correlation(self):
        d = details(verify=True); item = await self.add(d, event=browser(d)); ticket = item.ticket
        await self.command("session_lock", locked=True)
        with self.assertRaises(ServiceError):
            await self.command("verification_result", request_id=item.local_id, ticket_id=ticket, verified=True)
        self.assertFalse(self.service.engine.browser_events)

    async def test_wake_requires_new_browser_evidence(self):
        d = details(verify=True); item = await self.add(d, event=browser(d))
        await self.command("wake")
        self.assertFalse(item.ticket); self.assertFalse(item.decision); self.assertFalse(self.service.engine.browser_events)

    async def test_manual_available_when_no_shared_id(self):
        d = details(); d["sasSessionId"] = ""
        item = await self.add(d)
        await self.command("manual_approve", request_id=item.local_id, number="07"); await self.settle()
        self.assertEqual(self.outcomes(), ["synthetic_accepted"])

    async def test_expiry_cancels_without_approval(self):
        item = await self.add(details(verify=True))
        item.deadline = time.monotonic() - 1
        await self.service.tick()
        self.assertEqual(self.outcomes(), ["expired"])

    async def test_synthetic_never_calls_network_sender(self):
        async def forbidden(*args): raise AssertionError("network")
        self.service.sender = forbidden
        with patch.object(socket, "socket", side_effect=AssertionError("network")):
            await self.command("demo", require_verification=False); await self.settle()
        self.assertEqual(self.outcomes(), ["synthetic_accepted"])

    async def test_live_serializer_truthful_silent_flag_and_uncertain_claim(self):
        self.service.synthetic = False
        self.service.credentials = credentials.validate(BUNDLE)
        captured = []
        async def fake(request, claim):
            claim(); captured.append(request.body); raise OSError("untrusted raw token must never escape")
        self.service.sender = fake
        d = details(); item = await self.add(d, event=browser(d)); await self.settle()
        self.assertEqual(self.outcomes(), ["unknown"]); self.assertTrue(self.store.consumed(item.digest))
        root = ET.fromstring(captured[0])
        self.assertEqual([e.text for e in root.iter() if e.tag.endswith("completedInteractively")], ["no"])
        self.assertNotIn(BUNDLE["account"]["secret"].encode(), captured[0])
        self.assertNotIn("untrusted", json.dumps(self.events))
        await self.add(d); await self.settle(); self.assertEqual(len(captured), 1)

    async def test_recheck_after_connection_before_send(self):
        self.service.synthetic = False; self.service.credentials = credentials.validate(BUNDLE)
        async def fake(request, claim):
            self.service.locked = True
            claim()
            raise AssertionError("must not send")
        self.service.sender = fake
        d = details(); item = await self.add(d, event=browser(d)); await self.settle()
        self.assertFalse(self.store.consumed(item.digest)); self.assertEqual(self.outcomes(), ["cancelled_before_send"])

    async def test_browser_reset_during_connect_cancels_before_send_without_reconnect(self):
        self.service.synthetic = False; self.service.credentials = credentials.validate(BUNDLE)
        reached, resume = asyncio.Event(), asyncio.Event()
        writes = []
        async def fake(request, claim):
            reached.set(); await resume.wait(); claim(); writes.append(request)
            return response()
        self.service.sender = fake
        self.service.connection = "connected"
        d = details(); item = await self.add(d, event=browser(d))
        await asyncio.wait_for(reached.wait(), 1)
        await self.command("browser_reset")
        self.assertEqual(self.service.connection, "connected")
        self.assertFalse(self.service.engine.browser_events)
        resume.set(); await self.settle()
        self.assertFalse(writes); self.assertFalse(self.store.consumed(item.digest))
        self.assertEqual(self.outcomes(), ["cancelled_before_send"])

    async def test_browser_reset_revokes_automatic_ticket_but_retains_manual_ticket(self):
        d = details(verify=True); item = await self.add(d, event=browser(d)); ticket = item.ticket
        event = [e for e in self.events if e["event"] == "verification_required"][-1]
        self.assertEqual(event["mode"], "automatic")
        await self.command("browser_reset")
        self.assertFalse(item.ticket)
        with self.assertRaises(ServiceError):
            await self.command("verification_result", request_id=item.local_id, ticket_id=ticket, verified=True)
        await self.command("manual_approve", request_id=item.local_id, number="42")
        ticket = item.ticket
        event = [e for e in self.events if e["event"] == "verification_required"][-1]
        self.assertEqual(event["mode"], "manual")
        await self.command("browser_reset")
        self.assertEqual(item.ticket, ticket)

    async def test_correlation_status_reports_fixed_reason_without_identifier(self):
        d = details(verify=True); item = await self.add(d)
        mismatched = browser(d); mismatched["session_id"] = str(uuid.uuid4())
        await self.command("browser_event", browser=mismatched)
        pending = [e for e in self.events if e["event"] == "pending"]
        self.assertEqual(pending[-1]["status"], "session_unmatched")
        before = len(pending)
        await self.command("browser_event", browser=mismatched)
        self.assertEqual(len([e for e in self.events if e["event"] == "pending"]), before)
        self.assertNotIn(d["sasSessionId"], json.dumps(pending))
        self.assertNotIn(mismatched["session_id"], json.dumps(pending))
        self.assertTrue(pending[-1]["manual_available"])

    async def test_automatic_required_context_has_no_approval_button(self):
        d = details(context=True); await self.add(d, event=browser(d))
        pending = [e for e in self.events if e["event"] == "pending"][-1]
        self.assertEqual(pending["status"], "show_context")
        self.assertFalse(pending["manual_available"])

    async def test_disabling_automatic_reenables_manual_context_without_new_browser_event(self):
        d = details(context=True); item = await self.add(d, event=browser(d))
        self.assertTrue(item.decision)
        await self.command("settings", automatic=False)
        pending = [e for e in self.events if e["event"] == "pending"][-1]
        self.assertTrue(pending["manual_available"])
        self.assertEqual(pending["status"], "unique_local_match")
        self.assertFalse(item.decision)

    async def test_no_automatic_request_when_setting_off(self):
        await self.command("settings", automatic=False)
        d = details(); await self.add(d, event=browser(d)); await self.settle()
        self.assertFalse(self.outcomes())

    async def test_only_transient_failures_receive_bounded_backoff(self):
        attempts, delays = [], []
        class Transient:
            def __init__(self, *args): pass
            async def run(self): attempts.append(1); raise ConnectionError("raw ignored")
        async def sleep(delay): delays.append(delay)
        self.service.synthetic = False; self.service.credentials = credentials.validate(BUNDLE)
        self.service.connector = Transient
        with patch("controller.asyncio.sleep", sleep): await self.service.connection_loop()
        self.assertEqual(len(attempts), 4); self.assertEqual(delays, [2, 10, 30])
        self.assertEqual(self.service.connection, "attention")
        self.assertEqual(self.events[-1]["detail"], "connection_failed_retry_paused")

    async def test_rejected_credentials_never_retry_or_register(self):
        attempts = []
        class Rejected:
            def __init__(self, *args): pass
            async def run(self): attempts.append(1); raise transport.TransportError("provider_credentials_rejected")
        self.service.synthetic = False; self.service.credentials = credentials.validate(BUNDLE)
        self.service.connector = Rejected
        await self.service.connection_loop()
        self.assertEqual(len(attempts), 1)
        self.assertEqual(self.events[-1]["detail"], "provider_credentials_rejected_no_rotation")

    async def test_protocol_failure_does_not_blindly_retry(self):
        attempts = []
        class Malformed:
            def __init__(self, *args): pass
            async def run(self): attempts.append(1); raise p.ProtocolError("untrusted-server-value")
        self.service.synthetic = False; self.service.credentials = credentials.validate(BUNDLE)
        self.service.connector = Malformed
        await self.service.connection_loop()
        self.assertEqual(len(attempts), 1)
        self.assertEqual(self.events[-1]["detail"], "provider_protocol_requires_attention")
        self.assertNotIn("untrusted", json.dumps(self.events))

    async def test_restart_duplicate_rejected_from_persistent_claim(self):
        d = details(); item = await self.add(d, event=browser(d)); await self.settle()
        self.service.seen.clear()
        await self.add(d); await self.settle()
        self.assertEqual(self.outcomes(), ["synthetic_accepted"])
        self.assertTrue(self.store.consumed(item.digest))


class StorageAndBundle(unittest.TestCase):
    def test_claim_survives_restart_and_exclusive_process(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve()
            store = StateStore(path, synthetic=True)
            self.assertTrue(store.claim("synthetic-digest")); self.assertFalse(store.claim("synthetic-digest"))
            with self.assertRaises(StateError): StateStore(path, synthetic=True)
            store.close()
            store = StateStore(path, synthetic=True)
            self.assertTrue(store.consumed("synthetic-digest")); store.close()
            with self.assertRaises(StateError): StateStore(path, synthetic=False)

    def test_reject_public_or_symlink_state(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve(); path.chmod(0o755)
            with self.assertRaises(StateError): StateStore(path)
            path.chmod(0o700); link = path / "symlink"; link.symlink_to(path, target_is_directory=True)
            with self.assertRaises(StateError): StateStore(link)

    def test_bundle_rejects_wrong_provider_missing_identity_and_extra_fields(self):
        credentials.validate(BUNDLE)
        for mutate in (lambda b: b["provider"].update(sender_id="123"), lambda b: b["account"].pop("method_id"),
                       lambda b: b["provider"].update(extra="secret"), lambda b: b.update(version=True)):
            bundle = copy.deepcopy(BUNDLE); mutate(bundle)
            with self.assertRaises(Exception): credentials.validate(bundle)

    def test_vendor_hashes_match_frozen_source(self):
        manifest = json.loads((SERVICE_DIR / "vendor/PROVENANCE.json").read_text())["sha256"]
        for original, digest in manifest.items():
            self.assertEqual(hashlib.sha256((SERVICE_DIR / "vendor" / Path(original).name).read_bytes()).hexdigest(), digest)

    def test_exporter_reads_private_confirmed_identity_and_requires_e06(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); private = root / ".secrets/push"; private.mkdir(parents=True, mode=0o700)
            def write(path, obj):
                path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                path.write_text(json.dumps(obj)); path.chmod(0o600)
            e05, e06 = "a" * 32, "b" * 32
            for name, run_id in (("e05", e05), ("e06", e06)): write(private / (name + "-attempt.lock"), {"run_id": run_id})
            write(private / e05 / "report.json", {"experiment": "E05", "run_id": e05, "enrollment_completed": True,
                  "confirmation_accepted": True, "device_token_validated": True, "dos_preventer_present": True})
            success = {"experiment": "E06", "run_id": e06, "same_mac_sign_in_approved": True,
                  "browser_sign_in_success_user_reported": True, "authentication_approvals_sent": 1, "error": None}
            write(private / e06 / "report.json", success)
            account = BUNDLE["account"]
            write(private / e05 / "activation.json", {"OathTokenSecretKey": account["secret"], "Username": account["username"],
                  "TenantId": account["tenant_id"], "AzureObjectId": account["object_id"]})
            write(private / e05 / "validation.json", {"username": account["username"], "groupKey": account["group_key"], "dosPreventer": account["dos_preventer"]})
            write(private / e05 / "confirmation.json", {"ConfirmActivationResult": "true", "phoneAppDetailId": account["method_id"]})
            write(private / "e02-setup/input.json", {"expected_account": account["username"]})
            checkin = p.CheckinCredentials(12345, 67890)
            config = SimpleNamespace(sender_id="275572744697", package="com.azure.authenticator")
            before = {f.relative_to(root): f.read_bytes() for f in root.rglob("*") if f.is_file()}
            with patch.object(credentials.e02, "load_identity", return_value=(config, checkin, BUNDLE["provider"]["token"])):
                bundle = credentials.export_research(root)
                self.assertEqual(bundle["account"]["method_id"], account["method_id"])
                self.assertEqual(before, {f.relative_to(root): f.read_bytes() for f in root.rglob("*") if f.is_file()})
                write(private / e06 / "report.json", {**success, "same_mac_sign_in_approved": False})
                with self.assertRaises(Exception): credentials.export_research(root)


class Transport(unittest.IsolatedAsyncioTestCase):
    async def test_stream_ack_schema_and_heartbeat(self):
        decoder = p.MCSDecoder(); decoded = decoder.feed(bytes([41]) + transport.stream_ack(9))[0]
        self.assertEqual(decoded.tag, 7)
        fields = p.decode_fields(decoded.payload)
        self.assertEqual(fields.one(2, 0), 1); self.assertEqual(fields.one(10, 0), 9)
        extension = p.decode_fields(fields.one(7, 2))
        self.assertEqual(extension.one(1, 0), 13); self.assertEqual(extension.one(2, 2), b"")

    async def test_post_revalidates_after_connect_no_retry(self):
        writes = []
        class Writer:
            def write(self, data): writes.append(data)
            async def drain(self): pass
        class Reader:
            async def read(self, size): return b""
        @asynccontextmanager
        async def fake(*args): yield Reader(), Writer()
        req = p.Request("https://synthetic.mobileappcommunicator.auth.microsoft.com/mac/Synthetic.svc/pad",
                        {"x-ms-mac-action": "phoneAppPinValidationRequest"}, b"synthetic")
        with patch.object(transport.e02, "connection", fake):
            with self.assertRaises(ServiceError):
                await transport.post_number(req, lambda: (_ for _ in ()).throw(ServiceError("locked")))
        self.assertFalse(writes)

    async def test_mcs_login_heartbeat_ack_data_ack_and_bounds(self):
        writes, dispatched = [], []
        login = p.mcs_frame(3, p.field(1, ""), first=True)
        ping = p.mcs_frame(0, b"")
        data = p.mcs_frame(8, b"synthetic-data")
        close = p.mcs_frame(4, b"")
        class Writer:
            def write(self, value): writes.append(value)
            async def drain(self): pass
        class Reader:
            def __init__(self): self.chunks = [login[:1], login[1:] + ping + data + close]
            async def read(self, size): return self.chunks.pop(0) if self.chunks else b""
        @asynccontextmanager
        async def fake(*args): yield Reader(), Writer()
        async def on_data(frame): dispatched.append(frame)
        async def connected(): pass
        conn = transport.MCSConnection(credentials.validate(BUNDLE), on_data, connected)
        with patch.object(transport.e02, "connection", fake):
            with self.assertRaises(ConnectionError): await conn.run()
        self.assertEqual(len(dispatched), 1)
        self.assertEqual(len(writes), 3)  # One login, one heartbeat ACK, one stream ACK.
        decoder = p.MCSDecoder()
        controls = decoder.feed(bytes([41]) + b"".join(writes[1:]))
        self.assertEqual([frame.tag for frame in controls], [1, 7])
        self.assertEqual(p.decode_fields(controls[1].payload).one(10, 0), 3)

    async def test_http_destination_allowlist_rejects_before_connection(self):
        request = p.Request("https://example.com/pad", {"x-ms-mac-action": "phoneAppPinValidationRequest"}, b"synthetic")
        with patch.object(transport.e02, "connection", side_effect=AssertionError("network")):
            with self.assertRaises(Exception): await transport.post_number(request, lambda: None)


class IPC(unittest.TestCase):
    def test_subprocess_synthetic_and_redacted_bad_input(self):
        with tempfile.TemporaryDirectory() as directory:
            commands = [{"version": 1, "command": "configure", "credentials": None, "settings": {"automatic": True}},
                        {"version": 1, "command": "session_lock", "locked": False},
                        {"version": 1, "command": "demo", "require_verification": False},
                        {"version": 1, "command": "not-a-command-sensitive-content"}]
            result = subprocess.run([sys.executable, "-I", str(SERVICE_DIR / "main.py"), "--synthetic", "--state-dir", str(Path(directory).resolve())],
                                    input="".join(json.dumps(c) + "\n" for c in commands), text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0); self.assertFalse(result.stderr)
            self.assertNotIn("sensitive-content", result.stdout)
            events = [json.loads(line) for line in result.stdout.splitlines()]
            self.assertEqual(events[0]["event"], "ready")
            self.assertTrue(any(e.get("code") == "unknown_command" for e in events))


if __name__ == "__main__": unittest.main()
