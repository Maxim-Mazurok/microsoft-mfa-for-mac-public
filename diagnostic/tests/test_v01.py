"""Synthetic callback continuation; no network or real secret access."""
import asyncio
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import v01 as x
import test_e02 as f


class V01(unittest.IsolatedAsyncioTestCase):
    async def test_one_validation_only_and_no_enrollment_claim(self):
        run, report, calls = f.Run(), x.e02.new_report(), []
        notice = x.ep.validation_notification({**f.PROPERTIES,
            "url": f.BASE[8:] + "/mac/SyntheticService.svc/?dc=synthetic&handler=route01"})
        async def post(kind, request, enrollment, run, report):
            calls.append(kind)
            self.assertIsNone(enrollment)
            self.assertNotIn(f.CODE.encode(), request.body)
            report["http_posts_attempted"] += 1
            return f.VALIDATION
        with patch.object(x.e02, "post", post):
            await x.perform((notice, f.TOKEN, f.ACCOUNT, "a" * 32), run, report)
        self.assertEqual(calls, ["validate"])
        self.assertTrue(report["dos_preventer_present"])
        self.assertFalse(report["enrollment_completed"])
        self.assertEqual(report["authentication_approvals_sent"], 0)
        self.assertNotIn("synthetic-dos", json.dumps(report))

    async def test_failure_never_retries(self):
        calls = []
        async def post(*args):
            calls.append(args[0]); raise TimeoutError("synthetic-private-detail")
        notice = x.ep.validation_notification(f.PROPERTIES)
        with patch.object(x.e02, "post", post):
            with self.assertRaises(TimeoutError):
                await x.perform((notice, f.TOKEN, f.ACCOUNT, "a" * 32), f.Run(), x.e02.new_report())
        self.assertEqual(calls, ["validate"])
