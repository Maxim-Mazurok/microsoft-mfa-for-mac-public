"""E05 continuation with no enrollment and no stale-request approval."""
import asyncio
from contextlib import asynccontextmanager
import json
from pathlib import Path
import socket
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import e06 as x
import test_e02 as f
import test_e05 as s
import test_mfa_protocol as m


class Continuation(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.dns = patch.object(socket, "getaddrinfo", side_effect=AssertionError("Real DNS forbidden")).start()
        self.addCleanup(patch.stopall)
    async def asyncTearDown(self): self.dns.assert_not_called()

    async def simulate(self, purpose="SETUP", phrase="APPROVE", stale_only=False):
        state, run, calls, prompts, queue = x.new_report(), f.Run(), [], [], asyncio.Queue()
        decoder = x.e02.p.MCSDecoder(); first = True
        def put(guid):
            nonlocal first
            raw = (bytes([41]) if first else b"") + f.data({**s.NOTICE, "guid": guid}); first = False
            for frame in decoder.feed(raw): queue.put_nowait(frame)
        class Writer:
            def write(self, data): pass
            async def drain(self): pass
        class MCS:
            def __init__(self, reader, writer, capture, report): self.writer = writer
            async def login(self, credentials):
                state['mcs_logins_attempted'] += 1; state['mcs_accepted'] = True
                put('synthetic-consumed-guid')
            async def frame(self): return await queue.get()
        @asynccontextmanager
        async def connection(host, port, kind, report):
            calls.append('mcs'); report['mcs_connections_attempted'] += 1
            yield None, Writer()
        async def number(kind, request, private, report):
            calls.append(kind); report['http_posts_attempted'] += 1; report[kind + '_posts_attempted'] += 1
            return b'<phoneAppPinValidationResponse><validationResult>6</validationResult></phoneAppPinValidationResponse>'
        class TTY:
            def show(self, text):
                if text.startswith('READY:'): put('synthetic-new-setup')
                if text.startswith('Now initiate a NEW'): put('synthetic-new-signin')
            async def ask(self, prompt, **kwargs):
                prompts.append(prompt)
                if 'number currently' in prompt: return '42'
                if 'Type APPROVE' in prompt: return phrase
                if 'Type DONE' in prompt: return 'DONE'
                if 'Type SIGNIN to test' in prompt: return 'SIGNIN'
                if 'Type SIGNEDIN' in prompt: return 'SIGNEDIN'
                raise AssertionError('unexpected synthetic prompt')
        config = SimpleNamespace(sender_id=x.e02.p03.SENDER, package=x.e02.p03.PACKAGE)
        ready = m.A, config, f.CREDS, frozenset({'synthetic-consumed-guid'}), frozenset({'synthetic-old-method'})
        with patch.object(x.e02, 'connection', connection), patch.object(x.e02, 'MCS', MCS), \
             patch.object(x.e05.transport, 'post', number), patch.object(x.e02, 'post', side_effect=AssertionError('Enrollment forbidden')):
            try: await x.session(ready, purpose, run, state, TTY(), Path('/synthetic'))
            except Exception as exc: state['error'] = x.e02.safe_error(exc)
        return state, calls, prompts

    async def test_existing_setup_then_signin_no_enrollment(self):
        state, calls, prompts = await self.simulate()
        self.assertEqual(calls, ['mcs', 'number', 'number'])
        self.assertEqual(state['http_posts_attempted'], 2)
        self.assertEqual(state['activate_posts_attempted'], 0)
        self.assertEqual(state['authentication_approvals_sent'], 2)
        self.assertTrue(state['same_mac_sign_in_approved'])
        self.assertEqual(sum('Type APPROVE' in q for q in prompts), 2)
        self.assertEqual(state['prior_session_messages_ignored'], 1)
        self.assertNotIn(m.A.username, json.dumps(state))

    async def test_direct_signin_single_consent_and_no_setup_mutation(self):
        state, calls, prompts = await self.simulate('SIGNIN')
        self.assertEqual(calls, ['mcs', 'number'])
        self.assertEqual(state['new_enrollment_requests'], 0)
        self.assertEqual(state['authentication_approvals_sent'], 1)
        self.assertTrue(state['same_mac_sign_in_approved'])

    async def test_cancel_stops_without_approval_or_retry(self):
        state, calls, _ = await self.simulate(phrase='CANCEL')
        self.assertEqual(calls, ['mcs'])
        self.assertEqual(state['authentication_approvals_sent'], 0)
        self.assertEqual(state['error'], 'approval_not_explicitly_confirmed')
