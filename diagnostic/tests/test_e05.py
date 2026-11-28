"""Continuous enrollment and explicit number matching; synthetic data only."""
import asyncio
import base64
from contextlib import asynccontextmanager
import json
import os
from pathlib import Path
import pty
import select
import signal
import socket
import sys
import termios
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import approval_protocol as a
import e05 as x
import test_e02 as f
import test_mfa_protocol as m
from local_terminal import Terminal

DETAILS = {"guid": "synthetic-auth-guid", "username": m.A.username, "groupKey": m.A.group_key,
    "phoneAppDetailId": m.A.method_id, "tenantId": m.A.tenant_id, "azureObjectId": m.A.object_id,
    "expiration": str(int(time.time()) + 90), "firstEntropyChallenge": "10", "secondEntropyChallenge": "20", "thirdEntropyChallenge": "30",
    "isAppLockRequired": "no", "authDetails": json.dumps({"ApplicationDisplayName": "Synthetic app", "Latitude": 0, "Longitude": 0})}
NOTICE = {**DETAILS, "source": "SAS", "type": "auth", "url": m.SERVICE}


def policy(raw): return base64.b64encode(raw).decode()


class Codec(unittest.TestCase):
    def approved(self, fields=DETAILS):
        return a.consent(fields, "42", "APPROVE", 100, now=1, app_lock_used=False,
                         app_context_shown=True, location_context_shown=True)

    def test_explicit_consent_number_and_guid_binding(self):
        for phrase in ("", "approve", "DENY"):
            with self.assertRaises(Exception):
                a.consent(DETAILS, "42", phrase, 100, now=1, app_lock_used=False, app_context_shown=True, location_context_shown=True)
        for number in ("", "100", "-1", "1\n", "automatic"):
            with self.assertRaises(Exception):
                a.consent(DETAILS, number, "APPROVE", 100, now=1, app_lock_used=False, app_context_shown=True, location_context_shown=True)
        with self.assertRaisesRegex(Exception, "binding"):
            a.number_request(m.A, m.SERVICE, {**DETAILS, "guid": "different"}, self.approved(), now=1)
        with self.assertRaisesRegex(Exception, "expired"):
            a.number_request(m.A, m.SERVICE, DETAILS, self.approved(), now=100)

    def test_absolute_expiry_and_monotonic_review_cap(self):
        deadline = a.expiry.deadline("1700000060", 500, now_monotonic=510, now_unix=1700000010)
        self.assertEqual(deadline, 560)
        self.assertEqual(a.expiry.deadline("1700009999", 500, now_monotonic=510, now_unix=1700000010), 620)
        with self.assertRaisesRegex(Exception, "expired"):
            a.expiry.deadline("1700000060", 500, now_monotonic=510, now_unix=1700000060)
        with self.assertRaisesRegex(Exception, "expired"):
            a.expiry.deadline("1700009999", 500, now_monotonic=621, now_unix=1700000010)
        for value in ('60', '', '1700000060.0', '1700000060000'):
            with self.assertRaises(Exception): a.expiry.timestamp(value)

    def test_wall_clock_expiry_rechecked_before_sending(self):
        with self.assertRaisesRegex(Exception, "expired"):
            a.number_request(m.A, m.SERVICE, DETAILS, self.approved(), now=1, unix_time=int(DETAILS['expiration']))

    def test_number_serialization_no_fabricated_attestation(self):
        req = a.number_request(m.A, m.SERVICE, DETAILS, self.approved(), now=1, unix_time=3000)
        root = ET.fromstring(req.body).find("request/phoneAppPinValidationRequest")
        self.assertEqual(root.findtext("phoneAppContext/guid"), DETAILS["guid"])
        self.assertFalse(root.findtext("phoneAppContext/oathCode"))
        self.assertEqual(root.find("pin").attrib, {"stored": "no"})
        for key, value in (("authenticate", "yes"), ("selectedEntropyNumber", "42"), ("oathCounter", "100"),
                           ("completedInteractively", "yes"), ("isAppLockUsed", "no")):
            self.assertEqual(root.findtext(key), value)
        proto = x.e02.p.decode_fields(base64.b64decode(root.findtext("appState")))
        self.assertEqual(proto.one(12, 0), 16); self.assertEqual(proto.one(8, 0), 1)
        self.assertFalse(any(n in (9, 10, 11, 13, 14) for n, _, _ in proto.values))
        self.assertEqual(req.url, "https://" + m.SERVICE + "/pad")

    def test_policy_blocks_pin_location_unknown_fields_and_missing_context(self):
        pin_policy = policy(x.e02.p.field(5, x.e02.p.field(1, 1)))
        for changes in ({"userCredentialPolicy": pin_policy}, {"returnLocationData": "yes"}, {"pinChangeRequired": "true"},
                        {"isAppLockRequired": "perhaps"}, {"expiration": "0"}, {"thirdEntropyChallenge": ""},
                        {"userCredentialPolicy": policy(x.e02.p.field(99, 1))}):
            with self.subTest(changes=changes), self.assertRaises(Exception): a.requirements({**DETAILS, **changes})
        enabled = policy(x.e02.p.field(2, x.e02.p.field(8, 0)))
        req, _ = a.requirements({**DETAILS, "userCredentialPolicy": enabled})
        self.assertTrue(req["app_lock"]); self.assertTrue(req["app_context"]); self.assertTrue(req["location_context"])
        with self.assertRaises(Exception): a.requirements({**DETAILS, "userCredentialPolicy": enabled, "authDetails": ""})
        with self.assertRaises(Exception): self.approved({**DETAILS, "isAppLockRequired": "yes"})

    def test_policy_duplicate_and_rich_context_rejection(self):
        for value in ("!bad", policy(x.e02.p.field(5, b"") * 2), policy(x.e02.p.field(2, x.e02.p.field(6, 99)))):
            with self.assertRaises(Exception): a.policy(value)
        for value in ('{"ApplicationDisplayName":"one","ApplicationDisplayName":"two"}', '{"Latitude":999,"Longitude":0}', '[]'):
            with self.assertRaises(Exception): a.context({"authDetails": value})

    def test_actual_policy_metadata_timestamp_and_reporting_wire_types(self):
        field = x.e02.p.field
        metadata = field(1, 'synthetic-version') + field(2, field(1, 123456) + field(2, 0))
        report = field(1, 1) + field(2, 123)
        parsed = a.policy(policy(field(1, metadata) + field(3, report)))
        self.assertFalse(parsed['approval_pin'])
        with self.assertRaises(Exception): a.policy(policy(field(3, field(2, 'wrong-wire-type'))))

    def test_push_account_binding_and_noninteractive_rejection(self):
        self.assertEqual(a.push_details(NOTICE, m.A)["username"], m.A.username)
        for change in ({"phoneAppDetailId": "other"}, {"groupKey": "other"}, {"username": "other"}, {"interactive": "false"},
                       {"url": "evil.invalid"}, {"guid": ""}):
            with self.assertRaises(Exception): a.push_details({**NOTICE, **change}, m.A)

    def test_response_codes_never_confuse_http_success_with_approval(self):
        for code in range(1, 12):
            raw = f'<phoneAppPinValidationResponse><validationResult>{code}</validationResult></phoneAppPinValidationResponse>'.encode()
            self.assertEqual(a.number_response(raw)["number_approval_accepted"], code == 6)
        with self.assertRaises(Exception):
            a.number_response(b'<phoneAppPinValidationResponse><validationResult>6</validationResult><validationResult>7</validationResult></phoneAppPinValidationResponse>')


class TerminalTests(unittest.IsolatedAsyncioTestCase):
    async def test_hidden_input_restores_echo(self):
        master, slave = os.openpty(); tty = Terminal.__new__(Terminal); tty.fd = slave
        before = termios.tcgetattr(slave)
        try:
            task = asyncio.create_task(tty.ask("Synthetic prompt", seconds=1))
            await asyncio.sleep(0)
            self.assertFalse(termios.tcgetattr(slave)[3] & termios.ECHO)
            os.write(master, b"synthetic-secret\n")
            self.assertEqual(await task, "synthetic-secret")
            self.assertEqual(termios.tcgetattr(slave), before)
        finally: os.close(master); os.close(slave)

    async def test_timeout_restores_echo_without_background_reader(self):
        master, slave = os.openpty(); tty = Terminal.__new__(Terminal); tty.fd = slave
        before = termios.tcgetattr(slave)
        try:
            with self.assertRaises(TimeoutError): await tty.ask("Synthetic prompt", seconds=0.01)
            self.assertEqual(termios.tcgetattr(slave), before)
        finally: os.close(master); os.close(slave)

    async def test_cancel_restores_echo(self):
        master, slave = os.openpty(); tty = Terminal.__new__(Terminal); tty.fd = slave
        before = termios.tcgetattr(slave)
        try:
            task = asyncio.create_task(tty.ask("Synthetic prompt", seconds=1))
            await asyncio.sleep(0)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError): await task
            self.assertEqual(termios.tcgetattr(slave), before)
        finally: os.close(master); os.close(slave)


class ControllingTerminalTests(unittest.TestCase):
    """Exercise /dev/tty through rtk, not only an unrelated openpty slave."""
    def child(self, body, answers):
        script = ('import asyncio,json,sys,termios\n'
                  f'sys.path.insert(0,{str(Path(__file__).resolve().parents[1])!r})\n'
                  'from local_terminal import Terminal\n'
                  'async def check():\n'
                  ' t=Terminal()\n'
                  ' try:\n' + body + '\n'
                  ' finally:t.close()\n'
                  'asyncio.run(check())\n')
        pid, fd = pty.fork()
        if pid == 0:
            os.execvp('rtk', ['rtk', 'proxy', sys.executable, '-c', script])
        output, sent, status = bytearray(), set(), None
        deadline = time.monotonic() + 8
        try:
            while time.monotonic() < deadline:
                if select.select([fd], [], [], 0.05)[0]:
                    try: data = os.read(fd, 4096)
                    except OSError: data = b''
                    output.extend(data)
                    self.assertLess(len(output), 32768)
                    for marker, value in answers.items():
                        if marker.encode() in output and marker not in sent:
                            os.write(fd, value.encode() + b'\n'); sent.add(marker)
                ended, code = os.waitpid(pid, os.WNOHANG)
                if ended:
                    status = code
                    break
            self.assertIsNotNone(status, "Controlling-terminal subprocess timed out")
            self.assertEqual(os.waitstatus_to_exitcode(status), 0, output.decode(errors='replace'))
            for answer in answers.values(): self.assertNotIn(answer.encode(), output)
            return output.decode()
        finally:
            os.close(fd)
            if status is None:
                os.killpg(pid, signal.SIGKILL); os.waitpid(pid, 0)

    def test_rtk_dev_tty_two_hidden_prompts(self):
        result = self.child(
            '  a=await t.ask("FIRST_INPUT_READY",seconds=2)\n'
            '  b=await t.ask("SECOND_INPUT_READY",seconds=2)\n'
            '  print(json.dumps({"two_hidden_answers_received":a=="synthetic-one" and b=="synthetic-two"}))',
            {'FIRST_INPUT_READY': 'synthetic-one', 'SECOND_INPUT_READY': 'synthetic-two'})
        self.assertIn('"two_hidden_answers_received": true', result)

    def test_rtk_dev_tty_timeout_restores_then_accepts_new_input(self):
        result = self.child(
            '  old=termios.tcgetattr(t.fd)\n'
            '  expired=False\n'
            '  try:await t.ask("NO_INPUT_TIMEOUT_CHECK",seconds=0.1)\n'
            '  except TimeoutError:expired=True\n'
            '  restored=termios.tcgetattr(t.fd)==old\n'
            '  answer=await t.ask("AFTER_TIMEOUT_READY",seconds=2)\n'
            '  print(json.dumps({"timeout_restored_and_reusable":expired and restored and answer=="synthetic-after-timeout"}))',
            {'AFTER_TIMEOUT_READY': 'synthetic-after-timeout'})
        self.assertIn('"timeout_restored_and_reusable": true', result)


class Session(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.dns = patch.object(socket, "getaddrinfo", side_effect=AssertionError("Real DNS forbidden")).start()
        self.addCleanup(patch.stopall)
    async def asyncTearDown(self): self.dns.assert_not_called()

    async def simulate(self, *, phrase="APPROVE", signin=True, rejected=False):
        calls, prompts, queue = [], [], asyncio.Queue()
        run = f.Run(); run.run_id = "a" * 32
        state = x.e02.new_report()
        state.update(heartbeat_replies_sent=0, prior_control_messages_ignored=0, prior_validation_messages_ignored=0,
                     maximum_http_posts=7, maximum_seconds=900, maximum_approvals=2)
        decoder = x.e02.p.MCSDecoder()
        first = True
        def put(props):
            nonlocal first
            raw = (bytes([41]) if first else b"") + f.data(props); first = False
            for frame in decoder.feed(raw): queue.put_nowait(frame)
        class Writer:
            def write(self, data): pass
            async def drain(self): pass
        class Stream:
            def __init__(self, reader, writer, capture, report): self.writer = writer
            async def login(self, credentials):
                state["mcs_logins_attempted"] += 1; state["mcs_accepted"] = True
                put(f.PROPERTIES)
            async def frame(self): return await queue.get()
        @asynccontextmanager
        async def connection(host, port, kind, report):
            calls.append("mcs"); report["mcs_connections_attempted"] += 1
            yield None, Writer()
        activation = f.soap("ActivateNew", {"ActivateNewResult": "true", "Username": m.A.username,
            "AzureObjectId": m.A.object_id, "TenantId": m.A.tenant_id, "ConfirmationCode": "synthetic-confirmation",
            "OathTokenSecretKey": m.A.secret, "OathTokenEnabled": "true"})
        async def post(kind, request, enrollment, private, report):
            calls.append(kind); report["http_posts_attempted"] += 1; report[kind + "_posts_attempted"] += 1
            report[kind + "_http_status"] = 200
            return {"activate": activation, "validate": f.VALIDATION, "confirm": f.CONFIRMATION}[kind]
        async def number_post(kind, request, private, report):
            calls.append(kind); report["http_posts_attempted"] += 1; report[kind + "_posts_attempted"] += 1
            return b'<phoneAppPinValidationResponse><validationResult>' + (b'7' if rejected else b'6') + b'</validationResult></phoneAppPinValidationResponse>'
        class TTY:
            def show(self, text):
                if text.startswith("ENROLLED."): put(NOTICE)
                if text.startswith("Now initiate a NEW"): put({**NOTICE, "guid": "synthetic-signin-guid"})
            async def ask(self, prompt, **kwargs):
                prompts.append(prompt)
                if "number currently" in prompt: return "42"
                if "Type APPROVE" in prompt: return phrase
                if "Type DONE" in prompt: return "DONE"
                if "test actual" in prompt: return "SIGNIN" if signin else "STOP"
                if "Type SIGNEDIN" in prompt: return "SIGNEDIN"
                raise AssertionError("unexpected synthetic prompt")
        config = SimpleNamespace(sender_id=x.e02.p03.SENDER, package=x.e02.p03.PACKAGE)
        with patch.object(x.e02, "connection", connection), patch.object(x.e02, "MCS", Stream), patch.object(x.e02, "post", post), \
             patch.object(x.transport, "post", number_post), patch.object(x.rt, "private_json", return_value=f.PROPERTIES):
            try:
                await x.session((m.A, config, f.CREDS, frozenset(), set()), f.ENROLLMENT, m.A.username, run, state, TTY(), Path('/synthetic'))
            except Exception as exc: state["error"] = x.e02.safe_error(exc)
        return state, calls, run, prompts

    async def test_full_continuous_flow_and_two_separate_deliberate_approvals(self):
        state, calls, run, prompts = await self.simulate()
        self.assertEqual(calls, ["mcs", "activate", "validate", "confirm", "number", "number"])
        self.assertTrue(state["same_mac_sign_in_approved"])
        self.assertEqual(state["authentication_approvals_sent"], 2)
        self.assertEqual(state["http_posts_attempted"], 5)
        self.assertEqual(sum("Type APPROVE" in prompt for prompt in prompts), 2)
        self.assertIn("setup-request-details.json", run.files)
        self.assertIn("signin-request-details.json", run.files)
        for value in (m.A.secret, m.A.token, m.A.username, "synthetic-auth-guid", '"42"'):
            self.assertNotIn(value, json.dumps(state))

    async def test_cancel_never_sends_approval(self):
        state, calls, _, _ = await self.simulate(phrase="CANCEL")
        self.assertEqual(calls, ["mcs", "activate", "validate", "confirm"])
        self.assertEqual(state["error"], "approval_not_explicitly_confirmed")

    async def test_setup_only_never_claims_actual_signin(self):
        state, calls, _, _ = await self.simulate(signin=False)
        self.assertFalse(state["same_mac_sign_in_approved"])
        self.assertEqual(state["authentication_approvals_sent"], 1)

    async def test_wrong_number_result_never_retried(self):
        state, calls, _, _ = await self.simulate(rejected=True)
        self.assertEqual(calls.count("number"), 1)
        self.assertEqual(state["error"], "number_approval_not_accepted")

    async def test_required_local_verification_failure_blocks_consent(self):
        class TTY:
            def show(self, text): pass
            async def ask(self, prompt, **kwargs): return "42" if "number currently" in prompt else "APPROVE"
        async def fail(root): return False
        with self.assertRaisesRegex(Exception, "verification_failed"):
            await x.explicit_consent(TTY(), Path('/synthetic'), m.A, {**DETAILS, "isAppLockRequired": "yes"}, time.monotonic(), fail)

    async def test_required_local_verification_success_is_reported_truthfully(self):
        class TTY:
            def show(self, text): pass
            async def ask(self, prompt, **kwargs): return "42" if "number currently" in prompt else "APPROVE"
        async def success(root): return True
        result = await x.explicit_consent(TTY(), Path('/synthetic'), m.A, {**DETAILS, "isAppLockRequired": "yes"}, time.monotonic(), success)
        self.assertTrue(result.app_lock_used)

    async def test_pump_heartbeat_replies_are_bounded(self):
        writes = []
        class Writer:
            def write(self, raw): writes.append(raw)
            async def drain(self): pass
        class Stream:
            writer = Writer()
            async def frame(self): return x.e02.p.Frame(0, b"")
        state = {"heartbeat_replies_sent": 0}
        pump = x.Pump(Stream(), state)
        await pump.run()
        with self.assertRaisesRegex(Exception, "heartbeat_reply_budget_exhausted"): await pump.frame()
        self.assertEqual(len(writes), 8)
        self.assertEqual(writes, [b'\x01\x00'] * 8)

    async def test_prior_guid_never_reaches_approval(self):
        class Stream:
            last_received = 0
        stream = Stream()
        async def receive(*args): stream.last_received = time.monotonic(); return NOTICE
        class TTY:
            def show(self, text): pass
            async def ask(self, *args, **kwargs): raise AssertionError("No consent prompt for a replay")
        state = x.e02.new_report()
        with patch.object(x, "receive_auth", receive), self.assertRaisesRegex(Exception, "guid_reuse"):
            await x.auth_phase('signin', stream, None, m.A, {NOTICE['guid']}, f.Run(), state, TTY(), Path('/synthetic'))
        self.assertEqual(state['authentication_approvals_sent'], 0)

    async def test_old_method_and_guid_replays_filtered_before_private_write(self):
        decoder = x.e02.p.MCSDecoder()
        props = [{**NOTICE, "phoneAppDetailId": "synthetic-old-method"},
                 {**NOTICE, "guid": "synthetic-old-guid"}, NOTICE]
        frames = decoder.feed(bytes([41]) + b''.join(f.data(v) for v in props))
        class Stream:
            async def frame(self): return frames.pop(0)
        state = x.e02.new_report(); run = f.Run()
        config = SimpleNamespace(sender_id=x.e02.p03.SENDER, package=x.e02.p03.PACKAGE)
        result = await x.receive_auth(Stream(), config, {"synthetic-old-guid"}, {"synthetic-old-method"}, run, state)
        self.assertEqual(result['guid'], NOTICE['guid'])
        self.assertEqual(state['older_research_method_messages_ignored'], 1)
        self.assertEqual(state['prior_session_messages_ignored'], 1)
        self.assertEqual(len(run.files), 1)
